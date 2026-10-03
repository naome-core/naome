//! A separate model-free client submits static external fixtures to the binary.
use ed25519_dalek::{Signer, SigningKey};
use naome_submission::{Admission, MAX_BYTES, SignedRequest, Submission, hex};
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Server {
    child: Child,
    address: String,
    context: String,
    directory: std::path::PathBuf,
}
impl Server {
    fn start() -> Self {
        let directory =
            std::env::temp_dir().join(format!("naome-submission-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("public-configuration.json");
        fs::write(&path, include_bytes!("fixtures/configuration.json")).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_naome-submission"))
            .args([path.to_str().unwrap(), "127.0.0.1:0"])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let startup: Value = serde_json::from_str(&line).unwrap();
        Self {
            child,
            address: startup["address"].as_str().unwrap().into(),
            context: startup["context"].as_str().unwrap().into(),
            directory,
        }
    }
    fn call(&self, bytes: &[u8]) -> Value {
        let mut stream = TcpStream::connect(&self.address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(bytes).unwrap();
        response(&mut stream)
    }
    fn signed(&self, nonce: u64, body: Submission) -> Vec<u8> {
        // Public, deliberately insecure fixture key; no real account or custody.
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut request = SignedRequest {
            context: self.context.clone(),
            key: hex(key.verifying_key().as_bytes()),
            nonce,
            payload: serde_json::to_string(&body).unwrap(),
            signature: String::new(),
        };
        request.signature = hex(&key.sign(&request.signing_bytes().unwrap()).to_bytes());
        serde_json::to_vec(&request).unwrap()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.directory);
    }
}
fn response(stream: &mut TcpStream) -> Value {
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).unwrap();
    let size = u32::from_be_bytes(prefix) as usize;
    assert!(size <= 4096);
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn external_fixture_client_exercises_three_apis_and_transport_failures() {
    let server = Server::start();
    let local =
        Admission::from_configuration(include_bytes!("fixtures/configuration.json")).unwrap();
    assert_eq!(server.context, local.context());
    assert_eq!(server.call(b"{invalid"), json!({"error":"request_schema"}));
    let mut oversized = TcpStream::connect(&server.address).unwrap();
    oversized
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    oversized
        .write_all(&((MAX_BYTES + 1) as u32).to_be_bytes())
        .unwrap();
    assert_eq!(response(&mut oversized), json!({"error":"frame_limit"}));
    // An incomplete frame exceeds its absolute deadline. The next complete
    // connection still succeeds without any nonce having been consumed.
    let mut stalled = TcpStream::connect(&server.address).unwrap();
    stalled
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stalled.write_all(&[0]).unwrap();
    let started = Instant::now();
    let mut byte = [0];
    assert_eq!(stalled.read(&mut byte).unwrap(), 0);
    assert!(started.elapsed() >= Duration::from_secs(1));
    let input = server.signed(
        1,
        Submission::Question {
            source: include_str!("fixtures/question.nao").into(),
        },
    );
    let question = server.call(&input);
    println!("question: {question}");
    assert_eq!(question["receipt"]["kind"], "question_admitted");
    let q = question["receipt"]["object"].as_str().unwrap().to_owned();
    let duplicate = server.call(&input);
    assert_eq!(
        duplicate["receipt"]["request"],
        question["receipt"]["request"]
    );
    assert_eq!(duplicate["receipt"]["duplicate"], true);
    let evaluation = server.call(&server.signed(
        2,
        Submission::Evaluation {
            question: q.clone(),
            interested: true,
            rationale: "Static human interest fixture".into(),
        },
    ));
    println!("evaluation: {evaluation}");
    assert_eq!(
        evaluation["receipt"]["kind"],
        "advisory_evaluation_admitted"
    );
    let proof = server.call(&server.signed(
        3,
        Submission::ProofCandidate {
            question: q,
            refutation: false,
            certificate: include_str!("fixtures/certificate.hex").trim().into(),
            dependencies: vec![],
        },
    ));
    println!("proof candidate: {proof}");
    assert_eq!(proof["receipt"]["kind"], "checker_valid_candidate");
    assert!(proof["receipt"]["proof"].is_string());
    assert_eq!(proof["receipt"]["selected"], false);
    assert_eq!(proof["receipt"]["finalized"], false);
    let forbidden = server.signed(
        4,
        Submission::Question {
            source: "invalid".into(),
        },
    );
    let mut changed: Value = serde_json::from_slice(&forbidden).unwrap();
    changed["signature"] = json!("00".repeat(64));
    assert_eq!(
        server.call(&serde_json::to_vec(&changed).unwrap()),
        json!({"error":"signature"})
    );
}

#[test]
fn non_loopback_startup_is_rejected() {
    let output = Command::new(env!("CARGO_BIN_EXE_naome-submission"))
        .args(["unused-public-file", "0.0.0.0:0"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("loopback address required")
    );
}
