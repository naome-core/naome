//! Infrastructure used by the process integration fixtures.

#[cfg(unix)]
mod relay;

#[cfg(unix)]
pub fn run_relay(config: &std::path::Path) {
    crate::resources::initialize_from_environment().unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(relay::run(config))
        .unwrap();
}

#[cfg(all(unix, feature = "system-tests"))]
pub fn seed_checked_question(directory: &std::path::Path, source: Vec<u8>) {
    use crate::{network, question};
    use std::time::Duration;

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let (handle, admin, inbox) = question::channel();
            let config = network::Config {
                directory: directory.into(),
                listen: "/ip4/127.0.0.1/tcp/0".into(),
                peers: vec![],
                discovery: Some(network::DiscoveryConfig {
                    mdns: false,
                    dht: false,
                    internet: false,
                    ..Default::default()
                }),
                formal_goal: None,
            };
            let node = tokio::spawn(network::test_run(
                config,
                inbox,
                Some(crate::mocks::select_question),
            ));
            tokio::time::timeout(Duration::from_secs(15), async {
                let admission = handle.admit_question_bytes(&source).await.unwrap().unwrap();
                assert!(matches!(
                    admission.outcome,
                    question::AdmissionOutcome::Admitted(_)
                ));
                admin.stop().await.unwrap();
                node.await.unwrap().unwrap();
            })
            .await
            .unwrap();
        });
}
