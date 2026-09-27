use super::*;
use ed25519_dalek::SigningKey;
use naome_ledger::AccountId;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
};

struct Gateway(Child);
impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wire(address: &str, body: &[u8]) -> Value {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(body).unwrap();
    let mut size = [0; 4];
    stream.read_exact(&mut size).unwrap();
    let mut reply = vec![0; u32::from_be_bytes(size) as usize];
    stream.read_exact(&mut reply).unwrap();
    serde_json::from_slice(&reply).unwrap()
}

#[test]
fn separate_author_gateway_and_validator_recover_exact_action_and_receipt() {
    let _guard = process_guard();
    let mut lab = Lab::new();
    lab.start(0);
    lab.wait(0, |_| true);
    let available = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = available.local_addr().unwrap().to_string();
    drop(available);
    let gateway_log = File::create(lab.root.join("gateway.log")).unwrap();
    let gateway_errors = File::create(lab.root.join("gateway.errors")).unwrap();
    let gateway = Gateway(
        Command::new(BIN)
            .args([
                "gateway",
                "serve",
                &lab.file("genesis.bin"),
                &lab.file("node-0/control.sock"),
                &address,
            ])
            .stdout(gateway_log)
            .stderr(gateway_errors)
            .spawn()
            .unwrap(),
    );

    let key_file = fs::read(lab.key(4)).unwrap();
    let key = SigningKey::from_bytes(key_file[9..].try_into().unwrap());
    let account = path_from_bytes(AccountId::for_key(key.verifying_key().as_bytes()).as_bytes());
    let started = Instant::now();
    let context = loop {
        let attempt = raw(&[
            "gateway".into(),
            "context".into(),
            address.clone(),
            account.clone(),
        ]);
        if attempt.status.success() {
            break serde_json::from_slice::<Value>(&attempt.stdout).unwrap();
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "gateway did not start: {}",
            fs::read_to_string(lab.root.join("gateway.errors")).unwrap()
        );
        thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(context["next_nonce"], 1);
    assert_eq!(context["height"], 0);
    assert_eq!(context["genesis"], lab.status(0).unwrap()["genesis"]);
    assert!(context["genesis_bytes"].as_str().unwrap().len() > 100);
    assert!(context.get("accounts").is_none());
    assert!(context.get("validators").is_none());
    assert!(context.get("control_socket").is_none());
    assert_eq!(
        command(&[
            "gateway".into(),
            "receipt".into(),
            address.clone(),
            "00".repeat(32)
        ])["status"],
        "unknown"
    );
    let downloaded = lab.file("participant-genesis.bin");
    let saved = command(&[
        "gateway".into(),
        "genesis".into(),
        address.clone(),
        downloaded.clone(),
    ]);
    assert_eq!(saved["genesis"], context["genesis"]);
    assert_eq!(
        fs::read(&downloaded).unwrap(),
        fs::read(lab.file("genesis.bin")).unwrap()
    );

    let action = lab.file("remote-action.bin");
    let result = command(&[
        "remote-submit".into(),
        address.clone(),
        downloaded.clone(),
        lab.key(4),
        path(example("question-a.nao")),
        "Gateway author question".into(),
        action.clone(),
    ]);
    assert_eq!(result["result"]["status"], "transported");
    let id = result["operation"].as_str().unwrap().to_owned();
    assert_eq!(
        command(&[
            "gateway".into(),
            "receipt".into(),
            address.clone(),
            id.clone()
        ])["status"],
        "pending"
    );
    let bytes = fs::read(&action).unwrap();
    let mut forged = bytes.clone();
    *forged.last_mut().unwrap() ^= 1;
    let invalid = wire(
        &address,
        serde_json::json!({"command":"submit","bytes":path_from_bytes(&forged)})
            .to_string()
            .as_bytes(),
    );
    assert!(invalid["error"].as_str().unwrap().contains("signature"));
    assert_eq!(
        fs::metadata(&action).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        command(&[
            "remote-send".into(),
            address.clone(),
            downloaded.clone(),
            action.clone()
        ])["operation"],
        id
    );
    assert_eq!(lab.status(0).unwrap()["pending_operations"], 1);

    let malformed = wire(&address, b"{invalid");
    assert!(!malformed["error"].as_str().unwrap().is_empty());
    let mut oversized = TcpStream::connect(&address).unwrap();
    oversized
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    oversized.write_all(&u32::MAX.to_be_bytes()).unwrap();
    let mut header = [0; 4];
    oversized.read_exact(&mut header).unwrap();
    let mut reply = vec![0; u32::from_be_bytes(header) as usize];
    oversized.read_exact(&mut reply).unwrap();
    assert!(
        serde_json::from_slice::<Value>(&reply).unwrap()["error"]
            .as_str()
            .unwrap()
            .contains("byte limit")
    );

    let mut child = lab.nodes[0].take().unwrap();
    child.kill().unwrap();
    child.wait().unwrap();
    lab.start(0);
    lab.wait(0, |status| {
        status["pending_operations"] == 1 && status["height"] == 0
    });
    assert_eq!(
        command(&[
            "gateway".into(),
            "receipt".into(),
            address.clone(),
            id.clone()
        ])["status"],
        "pending"
    );
    assert_eq!(
        command(&[
            "remote-send".into(),
            address.clone(),
            downloaded.clone(),
            action.clone()
        ])["operation"],
        id
    );
    assert_eq!(fs::read(&action).unwrap(), bytes);
    assert_eq!(lab.status(0).unwrap()["pending_operations"], 1);

    for node in 1..4 {
        lab.start(node);
    }
    lab.wait(0, |_| {
        command(&["receipt".into(), lab.config(0), id.clone()])["status"] == "finalized"
    });
    let final_receipt = command(&[
        "gateway".into(),
        "receipt".into(),
        address.clone(),
        id.clone(),
    ]);
    assert_eq!(final_receipt["status"], "finalized");
    assert_eq!(final_receipt["nonce"], 1);
    assert_eq!(
        command(&[
            "remote-send".into(),
            address.clone(),
            downloaded.clone(),
            action.clone()
        ])["result"]["status"],
        "finalized"
    );

    let archive = lab.file("gateway-archive");
    let export = raw(&["export".into(), lab.config(0), archive.clone()]);
    assert!(
        export.status.success(),
        "export: {}",
        String::from_utf8_lossy(&export.stderr)
    );
    let replay = command(&["verify".into(), lab.file("genesis.bin"), archive]);
    assert!(replay["height"].as_u64().unwrap() >= final_receipt["height"].as_u64().unwrap());
    let inspected = command(&[
        "inspect".into(),
        lab.file("genesis.bin"),
        lab.file("gateway-archive"),
        id.clone(),
        lab.file("gateway-inspect"),
    ]);
    assert_eq!(inspected["admission"]["height"], final_receipt["height"]);
    assert_eq!(
        inspected["admission"]["operation_index"],
        final_receipt["operation_index"]
    );

    drop(gateway);
    let available = TcpListener::bind("127.0.0.1:0").unwrap();
    let restarted_address = available.local_addr().unwrap().to_string();
    drop(available);
    let gateway = Gateway(
        Command::new(BIN)
            .args([
                "gateway",
                "serve",
                &lab.file("genesis.bin"),
                &lab.file("node-0/control.sock"),
                &restarted_address,
            ])
            .stdout(File::create(lab.root.join("gateway-restarted.log")).unwrap())
            .stderr(File::create(lab.root.join("gateway-restarted.errors")).unwrap())
            .spawn()
            .unwrap(),
    );
    let started = Instant::now();
    loop {
        let output = raw(&[
            "gateway".into(),
            "receipt".into(),
            restarted_address.clone(),
            id.clone(),
        ]);
        if output.status.success() {
            let recovered: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(recovered, final_receipt);
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(10));
        thread::sleep(Duration::from_millis(50));
    }

    // Repeated exact bytes remain idempotent, while the per-author intake
    // budget eventually refuses even harmless retries in this time window.
    let mut limited = false;
    for _ in 0..AUTHOR_RETRY_BUDGET {
        let output = raw(&[
            "gateway".into(),
            "submit".into(),
            restarted_address.clone(),
            downloaded.clone(),
            action.clone(),
        ]);
        if !output.status.success() {
            limited = String::from_utf8_lossy(&output.stderr).contains("author submit rate limit");
            break;
        }
    }
    assert!(limited);
    assert_eq!(lab.status(0).unwrap()["pending_operations"], 0);
    drop(gateway);
}

const AUTHOR_RETRY_BUDGET: usize = 20;
fn path_from_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
