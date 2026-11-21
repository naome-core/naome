use super::*;

struct Network {
    _scratch: tempfile::TempDir,
    root: PathBuf,
    router: Node,
    a: Node,
    b: Node,
}

fn config(node: &Node, peers: Value, discovery: Value) -> Result<()> {
    fs::write(
        node.path.join("node.json"),
        serde_json::to_vec(&json!({
            "listen":node.address, "peers":peers, "discovery":discovery
        }))?,
    )?;
    Ok(())
}

impl Network {
    fn new(name: &str) -> Result<Self> {
        let scratch = tempfile::tempdir()?;
        let root = match std::env::var_os("REP_ROUTE_TRIAL_DIRECTORY") {
            Some(dir) => {
                let path = PathBuf::from(dir).join(name);
                fs::create_dir_all(path.parent().context("parent")?)?;
                fs::create_dir(&path)?;
                path
            }
            None => scratch.path().into(),
        };
        let router = Node::init(root.join("R"))?;
        let a = Node::init(root.join("A"))?;
        let b = Node::init(root.join("B"))?;
        // R can establish authenticated routing connections to A and B.
        // Neither custodian grants R a REP channel.
        config(
            &router,
            json!([]),
            json!({
                "mode":"server","clients":[a.peer,b.peer],"external_address":router.address
            }),
        )?;
        Ok(Self {
            _scratch: scratch,
            root,
            router,
            a,
            b,
        })
    }

    fn client(
        &self,
        node: &Node,
        replicas: Value,
        advertised: Option<&str>,
        use_relay: bool,
    ) -> Result<()> {
        config(
            node,
            replicas,
            json!({
                "mode":"client","bootstrap_id":self.router.peer,"bootstrap_address":self.router.address,
                "allow_private_addresses":true,"external_address":advertised,"use_relay":use_relay
            }),
        )
    }

    fn discovered(reader: &Node, peer: &Node, address: &str) -> Result<Value> {
        reader.wait_status(|s| {
            s["discovered_addresses"][&peer.peer]
                .as_array()
                .is_some_and(|addresses| addresses.contains(&json!(address)))
        })
    }

    fn fetch(&mut self, name: &str) -> Result<Id> {
        let file = self.root.join(name);
        fs::write(&file, format!("REP transport trial {name}"))?;
        let blob = cli(
            &self.a.path,
            &["archive", "blob", file.to_str().context("input")?],
        )?;
        let head: Id = serde_json::from_value(cli(&self.a.path, &["archive", "snapshot", name])?)?;
        self.a.publish(head)?;
        self.b.mirrored(head, &self.a)?;
        let output = file.with_extension("received");
        let recovered = Command::new(BIN)
            .arg("--directory")
            .arg(&self.b.path)
            .args([
                "archive",
                "resolve",
                &head.to_string(),
                blob.as_str().context("blob")?,
            ])
            .arg(&output)
            .output()?;
        ensure!(recovered.status.success(), "resolve failed");
        assert_eq!(fs::read(output)?, fs::read(&file)?);
        Ok(head)
    }
}

#[test]
fn discovered_identity_and_address_do_not_grant_archive_access() -> Result<()> {
    let mut n = Network::new("discovery")?;
    n.client(&n.a, json!([]), None, false)?;
    n.client(&n.b, json!([{"id":n.a.peer}]), None, false)?;
    n.router.start()?;
    n.a.start()?;
    n.b.start()?;
    let head: Id =
        serde_json::from_value(cli(&n.a.path, &["archive", "snapshot", "private-group"])?)?;
    n.a.publish(head)?;
    let state = Network::discovered(&n.b, &n.a, &n.a.address)?;
    // B sees the signed route and attempts an ordinary TCP connection. A's
    // transport allowlist declines B after identity authentication.
    n.b.wait(|e| e["connected"] == n.a.peer || e["dial_failed"] == n.a.peer)?;
    assert_eq!(cli(&n.b.path, &["archive", "heads"])?, json!([]));
    assert_eq!(cli(&n.router.path, &["archive", "heads"])?, json!([]));
    assert_eq!(cli(&n.a.path, &["status"])?["connected_peers"], json!([]));
    fs::write(
        n.root.join("result.json"),
        serde_json::to_vec_pretty(&state)?,
    )?;
    Ok(())
}

#[test]
fn discovered_direct_connection_fetches_evidence_and_refreshes_a_moved_peer() -> Result<()> {
    let mut n = Network::new("direct")?;
    n.client(&n.a, json!([{"id":n.b.peer}]), None, false)?;
    n.client(&n.b, json!([{"id":n.a.peer}]), None, false)?;
    n.router.start()?;
    n.a.start()?;
    n.b.start()?;
    Network::discovered(&n.a, &n.b, &n.b.address)?;
    let initial =
        n.a.wait_status(|s| s["connections"][&n.b.peer] == "direct")?;
    let first = n.fetch("direct-inventory")?;
    n.b.stop()?;
    let old = n.b.address.clone();
    let reservation = TcpListener::bind("127.0.0.1:0")?;
    n.b.address = format!("/ip4/127.0.0.1/tcp/{}", reservation.local_addr()?.port());
    assert_ne!(n.b.address, old);
    n.b.reservation = Some(reservation);
    n.client(&n.b, json!([{"id":n.a.peer}]), None, false)?;
    n.b.start()?;
    let updated = Network::discovered(&n.a, &n.b, &n.b.address)?;
    assert!(
        !updated["discovered_addresses"][&n.b.peer]
            .as_array()
            .unwrap()
            .contains(&json!(old))
    );
    n.b.wait_status(|s| s["connections"][&n.a.peer] == "direct")?;
    let second = n.fetch("reconnected-direct-inventory")?;
    assert!(!fs::read_to_string(n.router.path.join("events.jsonl"))?.contains("\"relay_circuit\""));
    fs::write(
        n.root.join("result.json"),
        serde_json::to_vec_pretty(
            &json!({"first":first,"second":second,"initial":initial,"updated":updated}),
        )?,
    )?;
    Ok(())
}

#[test]
fn failed_direct_dial_falls_back_to_a_real_relay_circuit_and_reconnects() -> Result<()> {
    let mut n = Network::new("relay")?;
    // The advertised direct endpoints accept TCP but never complete a Noise
    // handshake. The production dialer must observe failure and choose a circuit.
    let blackhole = TcpListener::bind("127.0.0.1:0")?;
    let unreachable = format!("/ip4/127.0.0.1/tcp/{}", blackhole.local_addr()?.port());
    n.client(&n.a, json!([{"id":n.b.peer}]), Some(&unreachable), true)?;
    n.client(&n.b, json!([{"id":n.a.peer}]), Some(&unreachable), true)?;
    n.router.start()?;
    n.a.start()?;
    n.b.start()?;
    let initial =
        n.b.wait_status(|s| s["connections"][&n.a.peer] == "relay")?;
    let circuit = n.router.wait(|e| e.get("relay_circuit").is_some())?;
    let source = &circuit["relay_circuit"]["source"];
    let failure = if *source == n.a.peer {
        n.a.wait(|e| e["dial_failed"] == n.b.peer && e["route"] == "direct")?
    } else {
        assert_eq!(*source, n.b.peer);
        n.b.wait(|e| e["dial_failed"] == n.a.peer && e["route"] == "direct")?
    };
    let first = n.fetch("circuit-inventory")?;
    n.router.stop()?;
    let offline = n.a.wait_status(|s| s["connections"] == json!({}))?;
    n.router.start()?;
    let reconnected =
        n.b.wait_status(|s| s["connections"][&n.a.peer] == "relay")?;
    let second = n.fetch("reconnected-circuit-inventory")?;
    assert_eq!(cli(&n.router.path, &["archive", "heads"])?, json!([]));
    fs::write(
        n.root.join("result.json"),
        serde_json::to_vec_pretty(
            &json!({"first":first,"second":second,"direct_failure":failure,"circuit":circuit,"initial":initial,"offline":offline,"reconnected":reconnected}),
        )?,
    )?;
    Ok(())
}
