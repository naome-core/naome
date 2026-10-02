use super::{frame, terminal, usage};
use crate::{
    chatgpt::{
        self, ISSUER, ResponsesConfig, access,
        auth::{self, Session},
        credentials::{AccountRecord, Store},
        http::{Endpoints, Http},
        stream::{self, Stream},
    },
    node::{self, Node, budget::Phase},
    provider::ProviderConfig,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

// This RSA key is deliberately public test material, never a participant key.
const TEST_PEM: &[u8] =
    include_bytes!("../../../tests/fixtures/siwc-public-test-key/public-fixture-only.pem");
fn jwks() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/siwc-public-test-key/jwks.json"
    ))
    .unwrap()
}
fn jwt(client: &str, nonce: Option<&str>, subject: &str) -> String {
    let now = auth::now().unwrap();
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("naome-public-fixture".into());
    encode(&header,&json!({"iss":ISSUER,"aud":client,"sub":subject,"exp":now+3600,"iat":now,"nonce":nonce,"email":"public.fixture@example.invalid"}),&EncodingKey::from_rsa_pem(TEST_PEM).unwrap()).unwrap()
}
fn tokens(client: &str, nonce: Option<&str>, subject: &str) -> Value {
    json!({"token_type":"Bearer","id_token":jwt(client,nonce,subject),"access_token":"fake-access-only","refresh_token":"fake-refresh-only","expires_in":3600,
        "scope":"openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"})
}
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "naome-siwc-http-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn config(&self) -> ResponsesConfig {
        ResponsesConfig {
            version: 1,
            credential_directory: self.0.join("credentials"),
            account_id: chatgpt::AccountInfo::identity_id(
                ISSUER,
                "client_fixture",
                "fixture-subject",
            ),
        }
    }
    fn save(&self, body: &Value) -> AccountRecord {
        let mut store = Store::open(&self.config().credential_directory, true).unwrap();
        let record = auth::validated_record(body, "client_fixture", None, &jwks(), None).unwrap();
        store.save(&record).unwrap();
        record
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        #[cfg(windows)]
        if let Ok(bytes) = fs::read(self.0.join("credentials/accounts.json"))
            && let Ok(value) = serde_json::from_slice::<Value>(&bytes)
            && let Some(host) = value["host_id"].as_str()
            && let Ok(entry) = keyring::Entry::new("NAOME SIWC credentials", host)
        {
            let _ = entry.delete_credential();
        }
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[derive(Default)]
struct State {
    calls: Vec<(String, String, String, String)>,
    accepted: usize,
    reader_failures: Vec<(&'static str, std::io::ErrorKind, usize, usize)>,
    nonce: Option<String>,
    challenge: Option<String>,
    token_error: Option<(u16, Value)>,
    model_hidden: bool,
    model_catalog: Option<(u16, Vec<u8>)>,
    model_catalog_delay: bool,
    response: Option<(u16, Vec<u8>)>,
    response_delay: bool,
    revoke_status: Option<u16>,
}
struct Server {
    base: String,
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Server {
    fn new() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(State::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let b = base.clone();
        let st = state.clone();
        let halt = stop.clone();
        let worker = thread::spawn(move || {
            let mut handlers: Vec<thread::JoinHandle<()>> = Vec::new();
            let mut failed = false;
            while !halt.load(Ordering::Acquire) {
                let mut i = 0;
                while i < handlers.len() {
                    if handlers[i].is_finished() {
                        if handlers.swap_remove(i).join().is_err() {
                            failed = true;
                            halt.store(true, Ordering::Release);
                        }
                    } else {
                        i += 1;
                    }
                }
                if halt.load(Ordering::Acquire) {
                    break;
                }
                match listener.accept() {
                    Ok((socket, _)) => {
                        st.lock().unwrap().accepted += 1;
                        let b = b.clone();
                        let st = st.clone();
                        let halt = halt.clone();
                        handlers.push(thread::spawn(move || serve_connection(socket, b, st, halt)));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => {
                        failed = true;
                        halt.store(true, Ordering::Release);
                    }
                }
            }
            for handler in handlers {
                failed |= handler.join().is_err();
            }
            assert!(!failed, "fixture connection handler failed");
        });
        Self {
            base,
            state,
            stop,
            worker: Some(worker),
        }
    }
    fn http(&self, seconds: u64) -> Http {
        Http::with_endpoints(
            Arc::new(AtomicBool::new(false)),
            seconds,
            Endpoints {
                discovery: format!("{}/discovery", self.base),
                authorize: format!("{}/authorize", self.base),
                token: format!("{}/token", self.base),
                jwks: format!("{}/jwks", self.base),
                revoke: Some(format!("{}/revoke", self.base)),
                api: format!("{}/v1", self.base),
            },
        )
        .unwrap()
    }
    fn calls(&self, path: &str) -> usize {
        self.state
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|(_, p, _, _)| p == path)
            .count()
    }
    fn diagnostics(&self) -> String {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let routes = state
            .calls
            .iter()
            .map(|(method, path, _, _)| (method, path))
            .collect::<Vec<_>>();
        format!(
            "routes={routes:?}; reader_failures={:?}",
            state.reader_failures
        )
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let result = self.worker.take().unwrap().join();
        if thread::panicking() {
            eprintln!("Fixture HTTP diagnostic: {}", self.diagnostics());
        }
        if !thread::panicking() {
            assert!(result.is_ok(), "fixture server panicked");
        }
    }
}
fn serve_connection(
    mut socket: TcpStream,
    b: String,
    st: Arc<Mutex<State>>,
    halt: Arc<AtomicBool>,
) {
    socket.set_nonblocking(false).unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let (method, path, body, bearer) = match read_request(&mut socket, &halt) {
        Ok(request) => request,
        Err(failure) => {
            st.lock().unwrap().reader_failures.push(failure);
            return;
        }
    };
    let (status, kind, value, delay) = {
        let mut s = st.lock().unwrap();
        s.calls
            .push((method.clone(), path.clone(), body.clone(), bearer));
        match path.as_str() {
                                "/discovery"=>(200,"application/json",serde_json::to_vec(&json!({"issuer":ISSUER,"authorization_endpoint":format!("{b}/authorize"),"token_endpoint":format!("{b}/token"),"jwks_uri":format!("{b}/jwks"),"revocation_endpoint":format!("{b}/revoke"),"id_token_signing_alg_values_supported":["RS256"]})).unwrap(),false),
                                "/jwks"=>(200,"application/json",serde_json::to_vec(&jwks()).unwrap(),false),
                                "/token"=>{
                                    let fields=url::form_urlencoded::parse(body.as_bytes()).map(|(k,v)|(k.into_owned(),v.into_owned())).collect::<std::collections::BTreeMap<_,_>>();
                                    assert_eq!(fields["client_id"],"client_fixture");
                                    if fields["grant_type"]=="authorization_code" {
                                        assert_eq!(fields["code"],"one-use-fixture-code");assert_eq!(URL_SAFE_NO_PAD.encode(Sha256::digest(fields["code_verifier"].as_bytes())),s.challenge.as_deref().unwrap());
                                        assert!(fields["redirect_uri"].starts_with("http://127.0.0.1:"));assert!(fields["redirect_uri"].ends_with("/auth/callback"));
                                    } else {assert_eq!(fields["grant_type"],"refresh_token");assert_eq!(fields["refresh_token"],"fake-refresh-only");}
                                    let (status,value)=s.token_error.clone().unwrap_or_else(||{let mut value=tokens("client_fixture",s.nonce.as_deref(),"fixture-subject");if fields["grant_type"]=="refresh_token" {value["access_token"]=json!("fake-access-rotated");value["refresh_token"]=json!("fake-refresh-rotated");}(200,value)});
                                    (status,"application/json",serde_json::to_vec(&value).unwrap(),false)
                                },
                                "/v1/models"=>{let (status,body)=s.model_catalog.clone().unwrap_or_else(||(200,serde_json::to_vec(&json!({"models":[{"slug":"gpt-6-luna","display_name":"GPT-6 Luna","visibility":if s.model_hidden{"hidden"}else{"list"}}]})).unwrap()));(status,"application/json",body,s.model_catalog_delay)},
                                "/v1/responses"=>{
                                    let (status,value)=s.response.clone().unwrap_or_else(||(200,frame(&terminal("completed",usage(),"{}"))));
                                    (status,if status==200{"text/event-stream"}else{"application/json"},value,s.response_delay)
                                },
                                "/revoke"=>(s.revoke_status.unwrap_or(200),"application/json",vec![],false),
                                _=>(404,"application/json",b"{}".to_vec(),false),
                            }
    };
    if delay {
        for _ in 0..60 {
            if halt.load(Ordering::Acquire) {
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
    }
    let header = format!(
        "HTTP/1.1 {status} Fixture\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\nOpenAI-Request-ID: fixture-request\r\n\r\n",
        value.len()
    );
    let _ = socket.write_all(header.as_bytes());
    let _ = socket.write_all(&value);
}

// Every accepted connection has an owner. Shutdown observes at most the
// existing read deadline; an idle peer cannot hold the listener itself.
fn read_part(socket: &mut TcpStream, part: &mut [u8], stop: &AtomicBool) -> std::io::Result<usize> {
    if stop.load(Ordering::Acquire) {
        return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
    }
    socket.read(part)
}
type FixtureRequest = (String, String, String, String);
type ReaderFailure = (&'static str, std::io::ErrorKind, usize, usize);
fn read_request(
    socket: &mut TcpStream,
    stop: &AtomicBool,
) -> Result<FixtureRequest, ReaderFailure> {
    socket
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let mut bytes = vec![];
    let mut part = [0; 4096];
    let (end, length) = loop {
        let n =
            read_part(socket, &mut part, stop).map_err(|e| ("header", e.kind(), bytes.len(), 0))?;
        if n == 0 {
            return Err(("header", std::io::ErrorKind::UnexpectedEof, bytes.len(), 0));
        }
        bytes.extend_from_slice(&part[..n]);
        assert!(bytes.len() < 1024 * 1024);
        if let Some(i) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
            let head = std::str::from_utf8(&bytes[..i]).unwrap();
            let length = head
                .lines()
                .filter_map(|l| l.split_once(':'))
                .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                .map_or(0, |(_, v)| v.trim().parse::<usize>().unwrap());
            break (i + 4, length);
        }
    };
    while bytes.len() < end + length {
        let n = read_part(socket, &mut part, stop)
            .map_err(|e| ("body", e.kind(), bytes.len(), end + length))?;
        if n == 0 {
            return Err((
                "body",
                std::io::ErrorKind::UnexpectedEof,
                bytes.len(),
                end + length,
            ));
        }
        bytes.extend_from_slice(&part[..n]);
    }
    let head = std::str::from_utf8(&bytes[..end]).unwrap();
    let mut first = head.lines().next().unwrap().split_whitespace();
    let method = first.next().unwrap().into();
    let path = first.next().unwrap().into();
    let bearer = head
        .lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        .map_or("", |(_, v)| v.trim())
        .into();
    Ok((
        method,
        path,
        String::from_utf8(bytes[end..end + length].to_vec()).unwrap(),
        bearer,
    ))
}
fn local_get(url: &url::Url) -> String {
    let mut socket = TcpStream::connect(("127.0.0.1", url.port().unwrap())).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let target = format!(
        "{}{}",
        url.path(),
        url.query().map_or(String::new(), |q| format!("?{q}"))
    );
    write!(
        socket,
        "GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        url.port().unwrap()
    )
    .unwrap();
    let mut reply = String::new();
    socket.read_to_string(&mut reply).unwrap();
    reply
}
fn config_provider(account: ResponsesConfig) -> ProviderConfig {
    ProviderConfig {
        responses: Some(account),
        codex_binary: PathBuf::new(),
        codex_home: PathBuf::new(),
        model: "gpt-6-luna".into(),
        timeout_seconds: 5,
        max_output_bytes: 256 * 1024,
        disabled_registries: Default::default(),
        pure_js: None,
    }
}

#[test]
fn jwt_identity_requires_pinned_signature_issuer_audience_nonce_and_key_use() {
    let token = jwt("client_fixture", Some("nonce"), "fixture-subject");
    assert!(auth::verify_identity(&token, "client_fixture", Some("nonce"), &jwks()).is_ok());
    assert!(auth::verify_identity(&token, "foreign_client", Some("nonce"), &jwks()).is_err());
    assert!(
        auth::verify_identity(&token, "client_fixture", Some("foreign_nonce"), &jwks()).is_err()
    );
    for fault in ["kid", "use", "alg", "duplicate"] {
        let mut keys = jwks();
        match fault {
            "kid" => keys["keys"][0]["kid"] = json!("other"),
            "use" => keys["keys"][0]["use"] = json!("enc"),
            "alg" => keys["keys"][0]["alg"] = json!("ES256"),
            "duplicate" => {
                let key = keys["keys"][0].clone();
                keys["keys"].as_array_mut().unwrap().push(key);
            }
            _ => unreachable!(),
        };
        assert!(
            auth::verify_identity(&token, "client_fixture", Some("nonce"), &keys).is_err(),
            "{fault}"
        );
    }
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("naome-public-fixture".into());
    let unsupported=encode(&header,&json!({"iss":ISSUER,"aud":"client_fixture","sub":"fixture-subject","iat":auth::now().unwrap(),"exp":auth::now().unwrap()+3600}),&EncodingKey::from_secret(b"public-fixture-hmac")).unwrap();
    assert!(auth::verify_identity(&unsupported, "client_fixture", None, &jwks()).is_err());
}

#[test]
fn identity_only_sign_in_is_retained_without_granting_plan_requests() {
    let directory = Directory::new();
    let mut body = tokens("client_fixture", None, "fixture-subject");
    body["scope"] = json!("openid profile email");
    body.as_object_mut().unwrap().remove("access_token");
    body.as_object_mut().unwrap().remove("expires_in");
    body.as_object_mut().unwrap().remove("refresh_token");
    body.as_object_mut().unwrap().remove("token_type");
    let record = directory.save(&body);
    assert!(record.info.signed_in);
    assert!(!record.info.plan_enabled);
    let server = Server::new();
    assert!(Session::with_http(&directory.config(), server.http(5)).is_err());
    assert_eq!(server.calls("/token"), 0);
    assert_eq!(server.calls("/v1/models"), 0);
    let store = Store::open(&directory.config().credential_directory, false).unwrap();
    assert!(
        store
            .record(&directory.config().account_id)
            .unwrap()
            .info
            .signed_in
    );
}

fn complete_browser(url: &str, state: Arc<Mutex<State>>) -> thread::JoinHandle<()> {
    let url = url::Url::parse(url).unwrap();
    thread::spawn(move || {
        let welcome = local_get(&url);
        assert!(welcome.contains("Continue with ChatGPT"));
        let path = welcome
            .split("href=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let consent = url.join(path).unwrap();
        let redirect = local_get(&consent);
        let location = redirect
            .lines()
            .find_map(|l| l.strip_prefix("Location: "))
            .unwrap();
        let authorize = url::Url::parse(location).unwrap();
        let fields = authorize
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(fields["client_id"], "dynamic_agent_client");
        assert_eq!(fields["agent_name_hint"], "NAOME");
        assert_eq!(fields["code_challenge_method"], "S256");
        {
            let mut state = state.lock().unwrap();
            state.nonce = Some(fields["nonce"].clone());
            state.challenge = Some(fields["code_challenge"].clone());
        }
        let mut callback = url::Url::parse(&fields["redirect_uri"]).unwrap();
        callback.query_pairs_mut().extend_pairs([
            ("state", fields["state"].as_str()),
            ("code", "one-use-fixture-code"),
            ("client_id", "client_fixture"),
        ]);
        let reply = local_get(&callback);
        assert!(reply.starts_with("HTTP/1.1 200") || reply.starts_with("HTTP/1.1 400"));
    })
}
#[test]
fn delayed_preconnection_does_not_block_http_or_fixture_shutdown() {
    let server = Server::new();
    let endpoint = url::Url::parse(&format!("{}/discovery", server.base)).unwrap();
    let mut idle = TcpStream::connect(("127.0.0.1", endpoint.port().unwrap())).unwrap();
    idle.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    thread::sleep(Duration::from_millis(100));
    assert!(local_get(&endpoint).starts_with("HTTP/1.1 200"));
    write!(
        idle,
        "GET /discovery HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        endpoint.port().unwrap()
    )
    .unwrap();
    let mut reply = String::new();
    idle.read_to_string(&mut reply).unwrap();
    assert!(reply.starts_with("HTTP/1.1 200"));
    let still_idle = TcpStream::connect(("127.0.0.1", endpoint.port().unwrap())).unwrap();
    let admitted = Instant::now() + Duration::from_secs(3);
    while server.state.lock().unwrap().accepted < 3 {
        assert!(
            Instant::now() < admitted,
            "idle fixture connection was not accepted"
        );
        thread::sleep(Duration::from_millis(5));
    }
    let before = Instant::now();
    drop(server);
    assert!(
        before.elapsed() < Duration::from_secs(3),
        "fixture shutdown did not join the idle handler"
    );
    drop(still_idle);
}

#[test]
fn actual_loopback_mock_sign_in_consumes_code_and_saves_issued_registration() {
    let directory = Directory::new();
    let server = Server::new();
    let browser = Arc::new(Mutex::new(None));
    let handle = browser.clone();
    let state = server.state.clone();
    let report = auth::sign_in_with_http(
        &directory.config().credential_directory,
        None,
        false,
        server.http(5),
        move |url| {
            *handle.lock().unwrap() = Some(complete_browser(url, state));
            Ok(())
        },
    )
    .unwrap();
    browser.lock().unwrap().take().unwrap().join().unwrap();
    assert_eq!(
        report["account"]["account_id"],
        directory.config().account_id
    );
    assert_eq!(report["model_requests"], 0);
    assert!(report["account"]["plan_enabled"].as_bool().unwrap());
    assert_eq!(server.calls("/token"), 1);
    assert_eq!(server.calls("/v1/responses"), 0);
    let store = Store::open(&directory.config().credential_directory, false).unwrap();
    assert!(store.pending_client().is_none());
    assert_eq!(
        store
            .record(&directory.config().account_id)
            .unwrap()
            .info
            .client_id,
        "client_fixture"
    );
    let safe = serde_json::to_string(&report).unwrap();
    assert!(!safe.contains("fake-access"));
    assert!(!safe.contains("fake-refresh"));
    assert!(!safe.contains("id_token"));
}
#[test]
fn failed_first_code_exchange_retains_issued_client_without_credentials() {
    for (code, expected) in [
        ("invalid_grant", "invalid_grant"),
        ("refresh_secret_example", "unknown_error"),
    ] {
        let directory = Directory::new();
        let server = Server::new();
        server.state.lock().unwrap().token_error = Some((
            400,
            json!({"error":code,"secret":"never-log-this-upstream-body"}),
        ));
        let browser = Arc::new(Mutex::new(None));
        let handle = browser.clone();
        let state = server.state.clone();
        let result = auth::sign_in_with_http(
            &directory.config().credential_directory,
            None,
            false,
            server.http(5),
            move |url| {
                *handle.lock().unwrap() = Some(complete_browser(url, state));
                Ok(())
            },
        );
        let handle = browser.lock().unwrap().take().unwrap_or_else(|| {
            panic!(
                "browser did not start: {result:?}; calls {:?}",
                server.state.lock().unwrap().calls
            )
        });
        handle.join().unwrap();
        let error = result.unwrap_err();
        assert!(error.contains(expected));
        assert!(!error.contains("refresh_secret_example"));
        assert!(!error.contains("never-log-this"));
        let store = Store::open(&directory.config().credential_directory, false).unwrap();
        assert_eq!(store.pending_client(), Some("client_fixture"));
        assert!(store.accounts().is_empty());
    }
}
#[test]
fn refresh_is_serialized_and_transient_failure_preserves_old_session() {
    let directory = Directory::new();
    directory.save(&tokens("client_fixture", None, "fixture-subject"));
    {
        let mut store = Store::open(&directory.config().credential_directory, false).unwrap();
        let mut record = store.record(&directory.config().account_id).unwrap();
        record.tokens.as_mut().unwrap().expires_at = auth::now().unwrap() + 30;
        store.save(&record).unwrap();
    }
    let server = Server::new();
    server.state.lock().unwrap().token_error =
        Some((503, json!({"error":"temporarily_unavailable"})));
    assert!(Session::with_http(&directory.config(), server.http(5)).is_err());
    {
        let store = Store::open(&directory.config().credential_directory, false).unwrap();
        assert!(
            store
                .record(&directory.config().account_id)
                .unwrap()
                .tokens
                .is_some()
        );
    }
    for body in [
        json!({"error":"refresh_secret_example"}),
        json!({"error":{"code":"refresh_secret_example"}}),
    ] {
        server.state.lock().unwrap().token_error = Some((503, body));
        let error = match Session::with_http(&directory.config(), server.http(5)) {
            Ok(_) => panic!("Unrecognized refresh failure unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(error.contains("HTTP 503, unknown_error"));
        assert!(!error.contains("refresh_secret_example"));
        let store = Store::open(&directory.config().credential_directory, false).unwrap();
        assert!(
            store
                .record(&directory.config().account_id)
                .unwrap()
                .tokens
                .is_some()
        );
    }
    server.state.lock().unwrap().token_error = None;
    let session = Session::with_http(&directory.config(), server.http(5)).unwrap();
    assert!(session.record.tokens.as_ref().unwrap().expires_at > auth::now().unwrap() + 60);
    assert_eq!(
        session
            .record
            .tokens
            .as_ref()
            .unwrap()
            .refresh_token
            .as_deref(),
        Some("fake-refresh-rotated")
    );
    assert_eq!(
        session.record.tokens.as_ref().unwrap().access_token,
        "fake-access-rotated"
    );
    assert!(Store::open(&directory.config().credential_directory, false).is_err());
    assert_eq!(server.calls("/token"), 4);
    drop(session);
}
#[test]
fn terminal_refresh_error_clears_tokens_but_preserves_registration() {
    let directory = Directory::new();
    directory.save(&tokens("client_fixture", None, "fixture-subject"));
    {
        let mut store = Store::open(&directory.config().credential_directory, false).unwrap();
        let mut record = store.record(&directory.config().account_id).unwrap();
        record.tokens.as_mut().unwrap().expires_at = auth::now().unwrap() + 30;
        store.save(&record).unwrap();
    }
    let server = Server::new();
    server.state.lock().unwrap().token_error = Some((400, json!({"error":"invalid_grant"})));
    assert!(Session::with_http(&directory.config(), server.http(5)).is_err());
    let store = Store::open(&directory.config().credential_directory, false).unwrap();
    let record = store.record(&directory.config().account_id).unwrap();
    assert!(record.tokens.is_none());
    assert!(!record.info.signed_in);
    assert_eq!(record.info.client_id, "client_fixture");
    assert_eq!(store.accounts().len(), 1);
}

#[test]
fn direct_http_uses_only_supported_fields_and_does_not_retry_errors() {
    let directory = Directory::new();
    directory.save(&tokens("client_fixture", None, "fixture-subject"));
    let server = Server::new();
    let session = Session::with_http(&directory.config(), server.http(5)).unwrap();
    let provider = config_provider(directory.config());
    let mut stream = Stream::new(provider.max_output_bytes);
    stream::request_with_session(
        &provider,
        "strict phase",
        crate::run::discovery_schema(),
        &session,
        &mut stream,
    )
    .unwrap();
    let calls = server.state.lock().unwrap().calls.clone();
    let (_, _, body, bearer) = calls
        .iter()
        .find(|(_, p, _, _)| p == "/v1/responses")
        .unwrap();
    let payload: Value = serde_json::from_str(body).unwrap();
    assert_eq!(bearer, "Bearer fake-access-only");
    assert!(payload["input"].is_array());
    assert_eq!(payload["store"], false);
    assert_eq!(payload["stream"], true);
    assert_eq!(payload["text"]["format"]["strict"], true);
    for field in [
        "max_output_tokens",
        "temperature",
        "background",
        "conversation",
        "previous_response_id",
        "tools",
        "multi_agent",
        "metadata",
    ] {
        assert!(payload.get(field).is_none(), "{field}");
    }
    assert_eq!(server.calls("/v1/responses"), 1);
    server.state.lock().unwrap().response=Some((429,serde_json::to_vec(&json!({"error":{"code":"subscription_sharing_usage_limit_exceeded","message":"fake-access-only"}})).unwrap()));
    let mut failed = Stream::new(provider.max_output_bytes);
    let error = stream::request_with_session(
        &provider,
        "strict phase",
        crate::run::discovery_schema(),
        &session,
        &mut failed,
    )
    .unwrap_err();
    assert!(!error.to_string().contains("fake-access-only"));
    assert_eq!(server.calls("/v1/responses"), 2);
    assert_eq!(failed.usage()["complete"], false);
}
#[test]
fn hidden_account_model_preflight_makes_no_post_and_keeps_credentials() {
    let directory = Directory::new();
    directory.save(&tokens("client_fixture", None, "fixture-subject"));
    let server = Server::new();
    server.state.lock().unwrap().model_hidden = true;
    let session = Session::with_http(&directory.config(), server.http(5)).unwrap();
    let provider = config_provider(directory.config());
    let mut stream = Stream::new(provider.max_output_bytes);
    assert!(
        stream::request_with_session(
            &provider,
            "phase",
            crate::run::discovery_schema(),
            &session,
            &mut stream
        )
        .is_err()
    );
    assert_eq!(server.calls("/v1/responses"), 0);
    assert!(session.record.tokens.is_some());
}

#[test]
fn model_diagnostic_is_one_selected_catalog_get_with_no_inference_or_gate_override() {
    for visibility in ["list", "hidden"] {
        let directory = Directory::new();
        directory.save(&tokens("client_fixture", None, "fixture-subject"));
        let server = Server::new();
        server.state.lock().unwrap().model_hidden = visibility == "hidden";
        let session = Session::with_http(&directory.config(), server.http(5)).unwrap();
        let report = session.model_diagnostics("gpt-6-luna").unwrap();
        assert_eq!(
            report["presence"],
            if visibility == "list" {
                "present_visible"
            } else {
                "present_hidden"
            }
        );
        assert_eq!(report["http_status"], 200);
        assert_eq!(report["model_requests"], 0);
        assert_eq!(report["catalog_get_attempts"], 1);
        assert_eq!(server.calls("/v1/models"), 1);
        assert_eq!(server.calls("/v1/responses"), 0);
        assert!(session.record.tokens.is_some());
        let state = server.state.lock().unwrap();
        assert!(
            state
                .calls
                .iter()
                .filter(|(_, path, _, _)| path == "/v1/models")
                .all(
                    |(method, _, _, bearer)| method == "GET" && bearer == "Bearer fake-access-only"
                )
        );
        drop(state);
        assert!(!report.to_string().contains("fake-access-only"));
        assert!(!report.to_string().contains("fixture-subject"));
        assert_eq!(
            session.require_model("gpt-6-luna").is_ok(),
            visibility == "list"
        );
        assert_eq!(server.calls("/v1/responses"), 0);
    }
}

#[test]
fn model_diagnostic_body_and_status_failures_never_post_or_expose_raw_data() {
    for response in [
        (200, b"invalid DO_NOT_EXPORT".to_vec()),
        (200, vec![b'x'; crate::chatgpt::http::MAX_MANAGEMENT_BYTES+1]),
        (403, br#"{"private":"DO_NOT_EXPORT"}"#.to_vec()),
        (200, serde_json::to_vec(&json!({"models":[{"slug":"other-model","display_name":"Other","visibility":"list"}]})).unwrap()),
    ] {
        let directory = Directory::new();
        directory.save(&tokens("client_fixture", None, "fixture-subject"));
        let server = Server::new();
        server.state.lock().unwrap().model_catalog = Some(response);
        let session = Session::with_http(&directory.config(), server.http(5)).unwrap();
        let result = session.model_diagnostics("gpt-6-luna");
        if let Ok(report) = &result {assert_eq!(report["presence"], "absent");}
        else {assert!(!result.unwrap_err().contains("DO_NOT_EXPORT"));}
        assert_eq!(server.calls("/v1/models"), 1);
        assert_eq!(server.calls("/v1/responses"), 0);
    }
}

#[test]
fn model_diagnostic_respects_deadline_cancellation_and_precontact_validation() {
    let directory = Directory::new();
    directory.save(&tokens("client_fixture", None, "fixture-subject"));
    let server = Server::new();
    let session = Session::with_http(&directory.config(), server.http(1)).unwrap();
    assert!(session.model_diagnostics("bad\nmodel").is_err());
    assert_eq!(server.calls("/v1/models"), 0);
    session.http.cancel.store(true, Ordering::Release);
    assert!(session.model_diagnostics("gpt-6-luna").is_err());
    assert_eq!(server.calls("/v1/models"), 0);
    drop(session);
    let session = Session::with_http(&directory.config(), server.http(1)).unwrap();
    server.state.lock().unwrap().model_catalog_delay = true;
    let before = std::time::Instant::now();
    assert!(session.model_diagnostics("gpt-6-luna").is_err());
    assert!(before.elapsed() < Duration::from_secs(3));
    assert_eq!(server.calls("/v1/models"), 1);
    assert_eq!(server.calls("/v1/responses"), 0);
}

#[test]
fn access_diagnostic_posts_fixed_body_once_without_changing_the_research_gate() {
    for text in ["OK", "different answer"] {
        let directory = Directory::new();
        directory.save(&tokens("client_fixture", None, "fixture-subject"));
        let server = Server::new();
        let mut response = terminal("completed", usage(), text);
        response["response"]["model"] = json!("gpt-6.1-sol");
        server.state.lock().unwrap().response = Some((200, frame(&response)));
        let session = Session::with_http(&directory.config(), server.http(5)).unwrap();
        let report = access::diagnose_with_session(&session, "gpt-6.1-sol").unwrap();
        assert_eq!(report["access_qualified"], true);
        assert_eq!(report["completed"], true);
        assert_eq!(report["returned_model"], "gpt-6.1-sol");
        assert_eq!(report["returned_model_matches"], true);
        assert_eq!(report["output_matches_ok"], text == "OK");
        assert_eq!(report["output_bytes"], text.len());
        assert_eq!(report["usage"]["complete"], true);
        assert_eq!(report["usage"]["total"]["totalTokens"], 27);
        assert_eq!(report["response_post_attempts"], 1);
        assert_eq!(server.calls("/v1/responses"), 1);
        assert_eq!(server.calls("/v1/models"), 0);
        let state = server.state.lock().unwrap();
        let (method, _, body, bearer) = state
            .calls
            .iter()
            .find(|(_, p, _, _)| p == "/v1/responses")
            .unwrap();
        assert_eq!(method, "POST");
        assert_eq!(bearer, "Bearer fake-access-only");
        assert_eq!(
            serde_json::from_str::<Value>(body).unwrap(),
            json!({
                "model":"gpt-6.1-sol","input":[{"role":"user","content":"Reply with exactly OK."}],"store":false,"stream":true
            })
        );
        drop(state);
        assert!(!report.to_string().contains("fake-access-only"));
        assert!(!report.to_string().contains("fixture-subject"));
        assert!(!report.to_string().contains("different answer"));
        assert!(session.require_model("gpt-6.1-sol").is_err());
        assert_eq!(server.calls("/v1/responses"), 1);
    }
}

#[test]
fn access_diagnostic_requires_the_requested_terminal_model_without_losing_known_usage() {
    for returned in [
        Value::Null,
        json!(17),
        json!("gpt-6-astra"),
        json!("sk-DO_NOT_EXPORT"),
    ] {
        let directory = Directory::new();
        directory.save(&tokens("client_fixture", None, "fixture-subject"));
        let server = Server::new();
        let mut response = terminal("completed", usage(), "OK");
        response["response"]["model"] = returned.clone();
        server.state.lock().unwrap().response = Some((200, frame(&response)));
        let session = Session::with_http(&directory.config(), server.http(5)).unwrap();
        let report = access::diagnose_with_session(&session, "gpt-6.1-sol").unwrap();
        assert_eq!(report["completed"], true);
        assert_eq!(report["access_qualified"], false);
        assert_eq!(report["returned_model_matches"], false);
        assert!(report["returned_model"].is_null());
        assert_eq!(report["usage"]["complete"], true);
        assert_eq!(report["usage"]["total"]["totalTokens"], 27);
        assert_eq!(report["consumption"], "reported_terminal_usage");
        assert!(!report.to_string().contains("DO_NOT_EXPORT"));
        assert_eq!(server.calls("/v1/responses"), 1);
        assert_eq!(server.calls("/v1/models"), 0);
    }
}

#[test]
fn access_diagnostic_http_failures_do_not_retry_or_export_error_messages() {
    for (status, code) in [
        (404, "model_not_found"),
        (401, "chatpass_v2_scope_not_authorized"),
        (403, "subscription_sharing_user_not_eligible"),
        (429, "subscription_sharing_usage_limit_exceeded"),
        (500, "DO_NOT_EXPORT"),
    ] {
        let directory = Directory::new();
        directory.save(&tokens("client_fixture", None, "fixture-subject"));
        let server = Server::new();
        server.state.lock().unwrap().response = Some((status, serde_json::to_vec(&json!({
            "error":{"code":code,"param":"model","message":"DO_NOT_EXPORT","account":"DO_NOT_EXPORT"}
        })).unwrap()));
        let session = Session::with_http(&directory.config(), server.http(5)).unwrap();
        let report = access::diagnose_with_session(&session, "gpt-6.1-sol").unwrap();
        assert_eq!(report["http_status"], status);
        assert_eq!(report["access_qualified"], false);
        assert_eq!(
            report["http_error"]["error_code"],
            if code == "DO_NOT_EXPORT" {
                "unrecognized_error_code"
            } else {
                code
            }
        );
        assert_eq!(report["http_error"]["error_param"], "model");
        assert_eq!(report["consumption"], "unknown");
        assert!(report["request_id"].is_null());
        assert!(!report.to_string().contains("DO_NOT_EXPORT"));
        assert_eq!(server.calls("/v1/responses"), 1);
        assert_eq!(server.calls("/v1/models"), 0);
    }
}

#[test]
fn access_diagnostic_requires_coherent_terminal_usage_and_bounded_output() {
    let mut missing = terminal("completed", usage(), "OK");
    missing["response"]["usage"] = Value::Null;
    let mut invalid = terminal("completed", usage(), "OK");
    invalid["response"]["usage"]["total_tokens"] = json!(1);
    let mut foreign = terminal("completed", usage(), "OK");
    foreign["response"]["id"] = json!("foreign-response");
    let mut conflict = frame(&terminal("completed", usage(), "OK"));
    conflict.extend(frame(&foreign));
    for response in [
        frame(&missing),
        frame(&invalid),
        conflict,
        b"data: [DONE]\n\n".to_vec(),
        vec![b'x'; 16 * 1024 + 1],
    ] {
        let directory = Directory::new();
        directory.save(&tokens("client_fixture", None, "fixture-subject"));
        let server = Server::new();
        server.state.lock().unwrap().response = Some((200, response));
        let session = Session::with_http(&directory.config(), server.http(5)).unwrap();
        let report = access::diagnose_with_session(&session, "gpt-6.1-sol").unwrap();
        assert_eq!(report["access_qualified"], false);
        assert_eq!(report["usage"]["complete"], false);
        assert_eq!(report["consumption"], "unknown");
        assert_eq!(server.calls("/v1/responses"), 1);
    }
    let directory = Directory::new();
    directory.save(&tokens("client_fixture", None, "fixture-subject"));
    let server = Server::new();
    server.state.lock().unwrap().response = Some((200, frame(&terminal("failed", usage(), "OK"))));
    let session = Session::with_http(&directory.config(), server.http(5)).unwrap();
    let report = access::diagnose_with_session(&session, "gpt-6.1-sol").unwrap();
    assert_eq!(report["access_qualified"], false);
    assert_eq!(report["usage"]["complete"], true);
    assert_eq!(report["usage"]["total"]["totalTokens"], 27);
}

#[test]
fn access_diagnostic_precontact_permission_cancel_and_shared_deadline_are_bounded() {
    let directory = Directory::new();
    let mut identity = tokens("client_fixture", None, "fixture-subject");
    identity["scope"] = json!("openid profile email");
    directory.save(&identity);
    let server = Server::new();
    assert!(Session::with_http(&directory.config(), server.http(5)).is_err());
    assert_eq!(server.calls("/v1/responses"), 0);
    directory.save(&tokens("client_fixture", None, "fixture-subject"));
    let session = Session::with_http(&directory.config(), server.http(1)).unwrap();
    assert!(access::diagnose_with_session(&session, "bad\nmodel").is_err());
    session.http.cancel.store(true, Ordering::Release);
    let report = access::diagnose_with_session(&session, "gpt-6.1-sol").unwrap();
    assert_eq!(report["response_post_attempts"], 0);
    assert_eq!(report["consumption"], "not_contacted");
    assert_eq!(server.calls("/v1/responses"), 0);
    drop(session);
    let mut store = Store::open(&directory.config().credential_directory, false).unwrap();
    let mut record = store.record(&directory.config().account_id).unwrap();
    record.tokens.as_mut().unwrap().expires_at = auth::now().unwrap() + 1;
    store.save(&record).unwrap();
    drop(store);
    server.state.lock().unwrap().response_delay = true;
    let before = Instant::now();
    let session = Session::with_http(&directory.config(), server.http(1)).unwrap();
    let report = access::diagnose_with_session(&session, "gpt-6.1-sol").unwrap();
    assert!(before.elapsed() < Duration::from_secs(3));
    assert_eq!(report["access_qualified"], false);
    assert_eq!(report["consumption"], "unknown");
    assert_eq!(server.calls("/token"), 1);
    assert_eq!(server.calls("/v1/responses"), 1);
    assert_eq!(server.calls("/v1/models"), 0);
}
#[test]
fn eof_without_terminal_and_network_deadline_leave_usage_incomplete() {
    for timeout in [false, true] {
        let directory = Directory::new();
        directory.save(&tokens("client_fixture", None, "fixture-subject"));
        let server = Server::new();
        {
            let mut s = server.state.lock().unwrap();
            s.response = Some((
                200,
                frame(
                    &json!({"type":"response.output_text.delta","sequence_number":0,"response_id":"resp_fixture","item_id":"msg_fixture","delta":"{}"}),
                ),
            ));
            s.response_delay = timeout;
        }
        let session = Session::with_http(&directory.config(), server.http(1)).unwrap();
        let provider = config_provider(directory.config());
        let mut stream = Stream::new(provider.max_output_bytes);
        assert!(
            stream::request_with_session(
                &provider,
                "phase",
                crate::run::discovery_schema(),
                &session,
                &mut stream
            )
            .is_err()
        );
        assert_eq!(stream.usage()["complete"], false);
        assert_eq!(server.calls("/v1/responses"), 1);
    }
}
#[test]
fn sign_out_revokes_before_local_clear_and_retains_registration_mapping() {
    let directory = Directory::new();
    directory.save(&tokens("client_fixture", None, "fixture-subject"));
    let server = Server::new();
    let report = auth::sign_out_with_http(&directory.config(), server.http(5)).unwrap();
    assert_eq!(report["remote_revocation_confirmed"], true);
    assert_eq!(server.calls("/revoke"), 1);
    let store = Store::open(&directory.config().credential_directory, false).unwrap();
    let record = store.record(&directory.config().account_id).unwrap();
    assert!(record.tokens.is_none());
    assert_eq!(record.info.client_id, "client_fixture");
}
#[test]
fn unconfirmed_revocation_is_reported_while_local_tokens_are_cleared() {
    let directory = Directory::new();
    directory.save(&tokens("client_fixture", None, "fixture-subject"));
    let server = Server::new();
    server.state.lock().unwrap().revoke_status = Some(503);
    let report = auth::sign_out_with_http(&directory.config(), server.http(5)).unwrap();
    assert_eq!(report["remote_revocation_confirmed"], false);
    assert_eq!(
        server.calls("/revoke"),
        3,
        "Observed fixture HTTP: {}",
        server.diagnostics()
    );
    let store = Store::open(&directory.config().credential_directory, false).unwrap();
    assert!(
        store
            .record(&directory.config().account_id)
            .unwrap()
            .tokens
            .is_none()
    );
}

#[test]
fn full_direct_mock_discover_evaluate_pending_solve_finalize_and_replay() {
    let directory = Directory::new();
    directory.save(&tokens("client_fixture", None, "fixture-subject"));
    let server = Server::new();
    let path = node::prepare_direct(
        &directory.0.join("prepared"),
        directory.config(),
        "gpt-6-luna",
    )
    .unwrap();
    let mut config = node::read_config(&path).unwrap();
    config.budgets.discoveries.amount = 1;
    config.budgets.evaluations.amount = 1;
    config.budgets.research.amount = 1500;
    let mut node = Node::initialize(config.clone(), 1_790_841_600).unwrap();
    let control = node::Control::default();
    let _watchdog = FixtureRunWatchdog::new(control.clone());
    let provider = config.provider.clone();
    let formula = json!({"op":"forall","variable":0,"body":{"op":"equal","left":0,"right":0}});
    let report=node.run_with(&control,||Ok(1_790_841_600),|reservation,control| {
        let value=match reservation.phase {
            Phase::Discover=>json!({"title":"Exact reflexivity","context":"Checked direct route fixture","formula_json":formula.to_string(),"definitions":[]}),
            Phase::Evaluate=>json!({"question_id":crate::state::hex(&reservation.target.unwrap()),"yes":true}),
            Phase::Solve=>{
                control.stop();json!({"question_id":crate::state::hex(&reservation.target.unwrap()),"outcome":"proof","source":"foundation = \"naome:zfc\"\nstatement = forall(x0, equal(x0, x0))\nproof:\n p0 = equality_reflexivity(x0)\n p1 = generalization(p0, x0)\n return p1\n","dependencies":[]})
            }
        };
        server.state.lock().unwrap().response=Some((200,frame(&terminal("completed",usage(),&value.to_string()))));
        let session=Session::with_http(&directory.config(),server.http(5)).unwrap();let mut stream=Stream::new(provider.max_output_bytes);
        let result=stream::request_with_session(&provider,&reservation.prompt_text,reservation.schema.clone(),&session,&mut stream);
        if result.is_err() { control.stop(); }
        crate::node::ProviderOutcome::from_provider_result(result,stream.usage(),stream.receipt.clone(),Some(stream.text.clone()))
    }).unwrap();
    assert_eq!(report["finalized_blocks"], 1);
    assert_eq!(report["pending_blocks"], 1);
    assert_eq!(report["local_credit"], 1);
    assert_eq!(report["attempts_admitted"], 3);
    assert_eq!(report["budgets"]["research_reported_tokens"]["spent"], 27);
    assert_eq!(server.calls("/v1/responses"), 3);
    let checkpoint = node.checkpoint().clone();
    drop(node);
    let replay = Node::replay(
        config,
        &directory.0.join("replayed"),
        Some((checkpoint.head, checkpoint.count)),
    )
    .unwrap();
    assert_eq!(replay["report"]["local_credit"], 1);
    assert_eq!(replay["report"]["finalized_blocks"], 1);
    assert_eq!(replay["provider_turns"], 0);
    assert_eq!(server.calls("/v1/responses"), 3);
}

// The fixture owns this timer, so failed early phases cannot strand its fixed
// clock in the production scheduler's intentional indefinite idle state.
struct FixtureRunWatchdog {
    done: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl FixtureRunWatchdog {
    fn new(control: node::Control) -> Self {
        let done = Arc::new(AtomicBool::new(false));
        let completed = done.clone();
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            while !completed.load(Ordering::Acquire) {
                if Instant::now() >= deadline {
                    control.stop();
                    break;
                }
                thread::sleep(Duration::from_millis(25));
            }
        });
        Self {
            done,
            worker: Some(worker),
        }
    }
}
impl Drop for FixtureRunWatchdog {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Release);
        let result = self.worker.take().unwrap().join();
        if !thread::panicking() {
            assert!(result.is_ok(), "fixture watchdog failed");
        }
    }
}

#[test]
fn received_direct_usage_survives_crash_before_settlement_and_unknown_blocks_renewal() {
    for known in [true, false] {
        let directory = Directory::new();
        directory.save(&tokens("client_fixture", None, "fixture-subject"));
        let server = Server::new();
        let path = node::prepare_direct(
            &directory.0.join("prepared"),
            directory.config(),
            "gpt-6-luna",
        )
        .unwrap();
        let mut config = node::read_config(&path).unwrap();
        config.budgets.discoveries.amount = 2;
        let mut node = Node::initialize(config.clone(), 1_790_841_600).unwrap();
        let reservation = node
            .reserve(
                Phase::Discover,
                None,
                1_790_841_600,
                "discovery".into(),
                crate::run::discovery_schema(),
            )
            .unwrap();
        server.state.lock().unwrap().response = Some((
            200,
            frame(&terminal(
                "completed",
                if known { usage() } else { Value::Null },
                "not-json",
            )),
        ));
        let session = Session::with_http(&directory.config(), server.http(5)).unwrap();
        let mut stream = Stream::new(config.provider.max_output_bytes);
        let result = stream::request_with_session(
            &config.provider,
            &reservation.prompt_text,
            reservation.schema.clone(),
            &session,
            &mut stream,
        );
        node.record_response(
            &reservation,
            crate::node::ProviderOutcome::from_provider_result(
                result,
                stream.usage(),
                stream.receipt.clone(),
                Some(stream.text.clone()),
            ),
        )
        .unwrap();
        drop(session);
        drop(node);
        let mut node = Node::open(config.clone()).unwrap();
        node.recover_provider().unwrap();
        let before = node.checkpoint().clone();
        node.recover_provider().unwrap();
        assert_eq!(node.checkpoint(), &before);
        let ledger = node
            .window_ledger(Phase::Discover, reservation.window.start)
            .unwrap()
            .unwrap();
        if known {
            assert_eq!(ledger.input + ledger.output, 27);
            assert!(!node.status("reopened").unwrap()["accounting_unknown"].is_string());
        } else {
            assert!(node.status("reopened").unwrap()["accounting_unknown"].is_string());
            assert!(matches!(
                node.step(1_790_841_600 + 86400).unwrap(),
                node::Step::Wait {
                    reason: node::WaitReason::AccountingUnknown,
                    ..
                }
            ));
        }
        assert_eq!(server.calls("/v1/responses"), 1);
        let cp = node.checkpoint().clone();
        drop(node);
        let replay = Node::replay(
            config,
            &directory.0.join("replay"),
            Some((cp.head, cp.count)),
        )
        .unwrap();
        assert_eq!(replay["provider_turns"], 0);
    }
}

#[test]
fn returned_renewal_identity_mismatch_does_not_replace_active_credentials() {
    let directory = Directory::new();
    directory.save(&tokens("client_fixture", None, "fixture-subject"));
    {
        let mut store = Store::open(&directory.config().credential_directory, false).unwrap();
        let mut record = store.record(&directory.config().account_id).unwrap();
        record.tokens.as_mut().unwrap().expires_at = auth::now().unwrap() + 30;
        store.save(&record).unwrap();
    }
    let server = Server::new();
    server.state.lock().unwrap().token_error =
        Some((200, tokens("client_fixture", None, "foreign-subject")));
    assert!(Session::with_http(&directory.config(), server.http(5)).is_err());
    let store = Store::open(&directory.config().credential_directory, false).unwrap();
    let record = store.record(&directory.config().account_id).unwrap();
    assert_eq!(record.info.subject, "fixture-subject");
    assert_eq!(
        record.tokens.as_ref().unwrap().refresh_token.as_deref(),
        Some("fake-refresh-only")
    );
}
#[test]
fn earliest_refresh_metadata_is_retained_and_a_future_bound_prevents_refresh() {
    let directory = Directory::new();
    let mut body = tokens("client_fixture", None, "fixture-subject");
    body["earliest_refresh_at"] = json!(auth::now().unwrap() + 600);
    directory.save(&body);
    {
        let mut store = Store::open(&directory.config().credential_directory, false).unwrap();
        let mut record = store.record(&directory.config().account_id).unwrap();
        assert_eq!(
            record.tokens.as_ref().unwrap().earliest_refresh_at,
            Some(body["earliest_refresh_at"].clone())
        );
        record.tokens.as_mut().unwrap().expires_at = auth::now().unwrap() + 30;
        store.save(&record).unwrap();
    }
    let server = Server::new();
    assert!(Session::with_http(&directory.config(), server.http(5)).is_err());
    assert_eq!(server.calls("/token"), 0);
}
#[cfg(unix)]
#[test]
fn insecure_or_symlinked_credential_files_are_rejected_before_network() {
    use std::os::unix::{fs::PermissionsExt, fs::symlink};
    let directory = Directory::new();
    directory.save(&tokens("client_fixture", None, "fixture-subject"));
    let credential = directory
        .config()
        .credential_directory
        .join(format!("account-{}.json", directory.config().account_id));
    fs::set_permissions(&credential, fs::Permissions::from_mode(0o644)).unwrap();
    let server = Server::new();
    assert!(Session::with_http(&directory.config(), server.http(5)).is_err());
    assert_eq!(server.calls("/token"), 0);
    assert_eq!(server.calls("/v1/models"), 0);
    fs::set_permissions(&credential, fs::Permissions::from_mode(0o600)).unwrap();
    let alias = directory.0.join("symlink-credentials");
    symlink(&directory.config().credential_directory, &alias).unwrap();
    assert!(Store::open(&alias, false).is_err());
}

#[test]
fn largest_accepted_direct_escaped_stream_and_terminal_receipt_fit_response_record() {
    for alphabet in ["a", "\\\"\n\u{0}", "λ"] {
        let directory = Directory::new();
        let path = node::prepare_direct(
            &directory.0.join("prepared"),
            directory.config(),
            "gpt-6-luna",
        )
        .unwrap();
        let mut config = node::read_config(&path).unwrap();
        config.budgets.discoveries.amount = 1;
        let mut node = Node::initialize(config.clone(), 1_790_841_600).unwrap();
        let reservation = node
            .reserve(
                Phase::Discover,
                None,
                1_790_841_600,
                "bounded output fixture".into(),
                crate::run::discovery_schema(),
            )
            .unwrap();
        let make = |n: usize| json!({"title":"Large rejection","context":alphabet.repeat(n),"formula_json":"{\"op\":\"forall\",\"variable\":0,\"body\":{\"op\":\"equal\",\"left\":0,\"right\":0}}","definitions":[]});
        let mut lower = 0;
        let mut upper = config.provider.max_output_bytes;
        while lower < upper {
            let n = lower + (upper - lower).div_ceil(2);
            if frame(&terminal("completed", usage(), &make(n).to_string())).len()
                <= config.provider.max_output_bytes
            {
                lower = n;
            } else {
                upper = n - 1;
            }
        }
        let wire = frame(&terminal("completed", usage(), &make(lower).to_string()));
        assert!(wire.len() > config.provider.max_output_bytes - 32);
        let mut stream = Stream::new(config.provider.max_output_bytes);
        stream.feed(&wire).unwrap();
        let result = stream.finish();
        assert!(result.is_ok());
        node.record_response(
            &reservation,
            crate::node::ProviderOutcome::from_provider_result(
                result,
                stream.usage(),
                stream.receipt.clone(),
                Some(stream.text.clone()),
            ),
        )
        .unwrap();
        node.recover_provider().unwrap();
        assert_eq!(
            node.window_ledger(Phase::Discover, reservation.window.start)
                .unwrap()
                .unwrap()
                .input,
            20
        );
        assert_eq!(node.status("known-rejection").unwrap()["local_credit"], 0);
        let checkpoint = node.checkpoint().clone();
        drop(node);
        let replay = Node::replay(
            config,
            &directory.0.join("replay"),
            Some((checkpoint.head, checkpoint.count)),
        )
        .unwrap();
        assert_eq!(replay["provider_turns"], 0);
        assert_eq!(replay["report"]["attempts_admitted"], 1);
    }
}
