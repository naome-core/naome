use super::*;
use crate::resources::ComputationState;

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
async fn authenticated_pause_and_resume_preserve_network_identity_interest_and_selection() {
    let directory = Directory::new();
    owner::update(&directory.0, "  logic\nλ  ").unwrap();
    let graph = Graph::open(&directory.0).unwrap();
    let control = Control::bind_test(&directory.0, graph.ownership()).unwrap();
    let selection = control.selection().unwrap();
    let endpoint = fs::read(directory.0.join("control.json")).unwrap();
    let active = control.computation.try_enter().unwrap();
    for _ in 0..2 {
        let status = exchange(&control, Operation::Pause).await;
        assert!(status.running);
        assert_eq!(status.computation, ComputationState::Pausing);
        assert_eq!(status.accepted_proofs, 3);
        assert_eq!(status.interest, "  logic\nλ  ");
        assert!(control.computation.try_enter().is_none());
    }
    drop(active);
    assert_eq!(
        exchange(&control, Operation::Status).await.computation,
        ComputationState::Paused
    );
    assert_eq!(
        exchange(&control, Operation::Interest("new interest".into()))
            .await
            .computation,
        ComputationState::Paused
    );
    let updated = control.selection().unwrap();
    assert_ne!(updated, selection);
    for _ in 0..2 {
        assert_eq!(
            exchange(&control, Operation::Resume).await.computation,
            ComputationState::Running
        );
        assert_eq!(control.selection().unwrap(), updated);
    }
    assert_eq!(
        fs::read(directory.0.join("control.json")).unwrap(),
        endpoint
    );
    assert!(!control.stopping());
}

#[tokio::test]
async fn stopped_computation_commands_do_not_initialize_or_start_a_node() {
    let directory = Directory::new();
    for paused in [true, false] {
        assert!(
            computation(&directory.0, paused)
                .await
                .unwrap_err()
                .contains("not running")
        );
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 0);
    }
}

#[tokio::test]
async fn an_invalid_control_token_cannot_pause_computation() {
    let directory = Directory::new();
    let graph = Graph::open(&directory.0).unwrap();
    let control = Control::bind_test(&directory.0, graph.ownership()).unwrap();
    let client = async {
        let mut stream = UnixStream::connect(&control.endpoint.socket).await.unwrap();
        write_frame(
            &mut stream,
            &Request {
                version: 1,
                token: "02".repeat(32),
                operation: Operation::Pause,
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
    assert_eq!(control.computation.state(), ComputationState::Running);
}
