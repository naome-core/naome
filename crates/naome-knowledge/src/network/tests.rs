use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

struct ConfigFile(PathBuf);

impl ConfigFile {
    fn new() -> Self {
        static SERIAL: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "naome-knowledge-config-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> PathBuf {
        self.0.join("config.json")
    }
}

impl Drop for ConfigFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn full_producer_queue_loads_with_worst_case_json_escaping() {
    let file = ConfigFile::new();
    let sources = vec!["\u{0001}".repeat(crate::MAX_PROOF_BYTES / 32); 32];
    let encoded = serde_json::to_vec_pretty(&json!({
        "directory": "node",
        "listen": "/ip4/127.0.0.1/tcp/0",
        "peers": [],
        "producer_sources": sources
    }))
    .unwrap();
    assert!(encoded.len() > 6 * crate::MAX_PROOF_BYTES);
    assert!(encoded.len() < MAX_CONFIG_BYTES);
    std::fs::write(file.path(), &encoded).unwrap();
    let loaded = read_config(&file.path()).unwrap();
    assert_eq!(loaded.producer_sources, sources);
    assert_eq!(loaded.directory, file.0.join("node"));
}

#[test]
fn oversized_configuration_still_rejects_before_decoding() {
    let file = ConfigFile::new();
    std::fs::write(file.path(), vec![b' '; MAX_CONFIG_BYTES + 1]).unwrap();
    assert_eq!(read_config(&file.path()).err().unwrap(), "file byte limit");
}

#[tokio::test]
async fn cli_peer_disable_cancels_final_interest_before_parent_commit() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize},
    };
    use tokio::sync::Notify;
    struct FinalInterest {
        dropped: Arc<AtomicBool>,
        notify: Arc<Notify>,
        peer: PeerId,
    }
    impl Drop for FinalInterest {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
            println!("test_final_interest_dropped peer={}", self.peer);
            self.notify.notify_one();
        }
    }
    let directory = ConfigFile::new();
    let sender_dir = directory.0.join("sender");
    let receiver_dir = directory.0.join("receiver");
    let make_identity = |path: &Path| {
        std::fs::create_dir_all(path).unwrap();
        let key = identity::Keypair::generate_ed25519();
        std::fs::write(
            path.join("identity.key"),
            key.to_protobuf_encoding().unwrap(),
        )
        .unwrap();
        key.public().to_peer_id()
    };
    let sender_peer = make_identity(&sender_dir);
    let receiver_peer = make_identity(&receiver_dir);
    let available_port = || {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    };
    let sender_port = available_port();
    let receiver_port = available_port();
    let config = |path: PathBuf, port, peer: PeerId, remote_port| Config {
        directory: path,
        listen: format!("/ip4/127.0.0.1/tcp/{port}"),
        peers: vec![Peer {
            id: peer.to_string(),
            address: format!("/ip4/127.0.0.1/tcp/{remote_port}"),
        }],
        discovery: Some(DiscoveryConfig {
            mdns: false,
            dht: false,
            ..Default::default()
        }),
        producer_sources: Vec::new(),
    };
    let mut sender_graph = Graph::open(&sender_dir).unwrap();
    let object = sender_graph
        .author("goal = all(x,eq(x,x)) proof: p0 = refl(x) p1 = gen(p0,x) return p1")
        .unwrap();
    let root = ProofId::from_bytes(id_bytes(&object.proof_id).unwrap());
    sender_graph.ingest(object, Instant::now()).unwrap();
    let target = *sender_graph
        .describe(root)
        .unwrap()
        .unwrap()
        .compile()
        .unwrap()
        .2
        .resolution_id();
    drop(sender_graph);
    let (sender_handle, sender_admin, sender_inbox) = crate::question::channel();
    let sender = tokio::spawn(run_with_questions(
        config(sender_dir, sender_port, receiver_peer, receiver_port),
        false,
        sender_inbox,
        |_| std::future::ready(Ok(true)),
    ));
    let (receiver_handle, receiver_admin, receiver_inbox) = crate::question::channel();
    let (commands, input) = mpsc::channel(8);
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let final_started = Arc::new(Notify::new());
    let started = final_started.clone();
    let released = Arc::new(Notify::new());
    let release = released.clone();
    let dropped = Arc::new(AtomicBool::new(false));
    let observed_drop = dropped.clone();
    let drop_notify = Arc::new(Notify::new());
    let notify = drop_notify.clone();
    let receiver = tokio::spawn(run_inner(
        config(
            receiver_dir.clone(),
            receiver_port,
            sender_peer,
            sender_port,
        ),
        false,
        receiver_inbox,
        Some(move |question: naome_authoring::CompiledQuestion| {
            let selected = *question.resolution_id() == target;
            let first = selected && observed.fetch_add(1, Ordering::SeqCst) == 0;
            let started = started.clone();
            let release = release.clone();
            let dropped = observed_drop.clone();
            let notify = notify.clone();
            async move {
                if !selected {
                    return Ok(false);
                }
                if first {
                    return Ok(true);
                }
                let _owned = FinalInterest {
                    dropped,
                    notify,
                    peer: sender_peer,
                };
                started.notify_one();
                release.notified().await;
                Ok(true)
            }
        }),
        input,
        None,
    ));
    tokio::time::timeout(Duration::from_secs(15), final_started.notified())
        .await
        .unwrap();
    assert_eq!(receiver_handle.context().await.unwrap().checked_proofs, 0);
    commands
        .send(Ok(
            json!({"command":"links","peers":[],"request":"disable-during-final"}),
        ))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), drop_notify.notified())
        .await
        .unwrap();
    assert!(dropped.load(Ordering::SeqCst));
    released.notify_waiters();
    let context = receiver_handle.context().await.unwrap();
    assert_eq!(context.checked_proofs, 0);
    assert_eq!(context.registered_questions, 0);
    receiver_admin.stop().await.unwrap();
    sender_admin.stop().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), receiver)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), sender)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    drop(sender_handle);
    assert!(Graph::open(&receiver_dir).unwrap().ids().is_empty());
    assert!(
        std::fs::read_dir(receiver_dir.join("objects"))
            .unwrap()
            .next()
            .is_none()
    );
}
