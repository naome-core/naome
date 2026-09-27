//! Keyless participant ingress. The validator's anchored pending journal owns
//! accepted bytes; this process has no action database or signing authority.

use super::{
    Result,
    control::{self, Request},
    files,
};
use naome_ledger::{
    AccountId,
    authentication::{SIGNED_OPERATION_MAX_BYTES, SignedOperation},
    profile::Genesis,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};

// A hex-encoded maximum action plus a short JSON envelope. One request per
// connection, with no retained request bodies or unbounded task queue.
const MAX_FRAME: usize = 2 * SIGNED_OPERATION_MAX_BYTES + 512;
const MAX_RESPONSE: usize = 512 * 1024;
const MAX_CONNECTIONS: usize = 16;
const WINDOW: Duration = Duration::from_secs(60);
const GLOBAL_REQUESTS: u16 = 512;
const CALLER_REQUESTS: u16 = 64;
const AUTHOR_SUBMITS: u16 = 16;

#[derive(Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum GatewayRequest {
    Context { account: String },
    Submit { bytes: String },
    Receipt { id: String },
}

struct Limits {
    since: Instant,
    global: u16,
    callers: BTreeMap<IpAddr, u16>,
    authors: BTreeMap<AccountId, u16>,
}
impl Limits {
    fn new() -> Self {
        Self {
            since: Instant::now(),
            global: 0,
            callers: BTreeMap::new(),
            authors: BTreeMap::new(),
        }
    }
    fn reset(&mut self) {
        if self.since.elapsed() >= WINDOW {
            self.since = Instant::now();
            self.global = 0;
            self.callers.clear();
            self.authors.clear();
        }
    }
    fn caller(&mut self, ip: IpAddr) -> bool {
        self.reset();
        if self.global >= GLOBAL_REQUESTS
            || (!self.callers.contains_key(&ip) && self.callers.len() >= 256)
        {
            return false;
        }
        let count = self.callers.entry(ip).or_default();
        if *count >= CALLER_REQUESTS {
            return false;
        }
        self.global += 1;
        *count += 1;
        true
    }
    fn author(&mut self, account: AccountId) -> bool {
        self.reset();
        if !self.authors.contains_key(&account) && self.authors.len() >= 256 {
            return false;
        }
        let count = self.authors.entry(account).or_default();
        if *count >= AUTHOR_SUBMITS {
            return false;
        }
        *count += 1;
        true
    }
}

struct Server {
    genesis: Genesis,
    genesis_bytes: String,
    socket: PathBuf,
    limits: Mutex<Limits>,
}

async fn read_frame(stream: &mut TcpStream, maximum: usize) -> Result<Vec<u8>> {
    let size = stream.read_u32().await? as usize;
    if size == 0 || size > maximum {
        return Err("gateway frame exceeds byte limit".into());
    }
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}
async fn write_frame(stream: &mut TcpStream, bytes: &[u8], maximum: usize) -> Result<()> {
    if bytes.len() > maximum {
        return Err("gateway frame exceeds byte limit".into());
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(bytes).await?;
    Ok(())
}

async fn handle(server: &Server, request: GatewayRequest) -> Result<Value> {
    match request {
        GatewayRequest::Context { account } => {
            let _: [u8; 32] = files::unhex(&account)?;
            let mut context =
                control::call_socket(&server.socket, Request::AuthorContext { account }).await?;
            if context["genesis"] != files::hex(server.genesis.id().as_bytes()) {
                return Err("validator genesis changed".into());
            }
            context["genesis_bytes"] = json!(server.genesis_bytes);
            Ok(context)
        }
        GatewayRequest::Submit { bytes } => {
            if bytes.len() > 2 * server.genesis.profile().limits().record_bytes as usize
                || !bytes.len().is_multiple_of(2)
                || !bytes.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err("signed action exceeds bound or is not hexadecimal".into());
            }
            let raw = decode_hex(&bytes)?;
            let action = SignedOperation::decode(&raw)?;
            action.verify_signature(&server.genesis)?;
            let author = action.author();
            if !server
                .limits
                .lock()
                .expect("gateway limits mutex")
                .author(author)
            {
                return Err("author submit rate limit".into());
            }
            let id = action.id();
            let result = control::call_socket(&server.socket, Request::Submit { bytes }).await?;
            if !matches!(result["status"].as_str(), Some("transported" | "finalized"))
                || (result["status"] == "transported"
                    && result["operation"] != files::hex(id.as_bytes()))
            {
                return Err("validator returned an invalid action acknowledgement".into());
            }
            Ok(
                json!({"operation":files::hex(id.as_bytes()),"result":result,
                "notice":"transport acceptance is not finalized admission"}),
            )
        }
        GatewayRequest::Receipt { id } => {
            let _: [u8; 32] = files::unhex(&id)?;
            control::call_socket(&server.socket, Request::ActionStatus { id }).await
        }
    }
}

async fn connection(mut stream: TcpStream, ip: IpAddr, server: Arc<Server>) {
    let result = tokio::time::timeout(Duration::from_secs(40), async {
        let bytes =
            tokio::time::timeout(Duration::from_secs(5), read_frame(&mut stream, MAX_FRAME))
                .await??;
        if !server
            .limits
            .lock()
            .expect("gateway limits mutex")
            .caller(ip)
        {
            return Err::<Value, Box<dyn std::error::Error + Send + Sync>>(
                "caller or global request rate limit".into(),
            );
        }
        let request: GatewayRequest = serde_json::from_slice(&bytes)?;
        handle(&server, request).await
    })
    .await;
    let value = match result {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => json!({"error":error.to_string()}),
        Err(_) => {
            json!({"error":"gateway request timed out; query receipt before retrying exact bytes"})
        }
    };
    if let Ok(bytes) = serde_json::to_vec(&value) {
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            write_frame(&mut stream, &bytes, MAX_RESPONSE),
        )
        .await;
    }
}

async fn serve(genesis_path: &Path, socket: &Path, address: SocketAddr) -> Result<()> {
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err("gateway listens only on an explicit loopback address and nonzero port".into());
    }
    let bytes = files::read(genesis_path, 128 * 1024, false)?;
    let genesis = Genesis::decode(&bytes)?;
    // A gateway never opens a key or authority store. Confirm its public
    // genesis against the live validator before admitting any TCP request.
    let probe = control::call_socket(
        socket,
        Request::AuthorContext {
            account: "00".repeat(32),
        },
    )
    .await?;
    if probe["genesis"] != files::hex(genesis.id().as_bytes()) {
        return Err("gateway and validator genesis differ".into());
    }
    let listener = TcpListener::bind(address).await?;
    let server = Arc::new(Server {
        genesis,
        genesis_bytes: files::hex(&bytes),
        socket: socket.to_owned(),
        limits: Mutex::new(Limits::new()),
    });
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    println!(
        "{}",
        json!({"status":"gateway_listening","address":address,"genesis":files::hex(server.genesis.id().as_bytes())})
    );
    loop {
        tokio::select! {
            result=listener.accept()=>{
                let (stream,peer)=result?;
                if let Ok(permit)=permits.clone().try_acquire_owned() {
                    let server=server.clone();
                    tokio::spawn(async move {let _permit=permit;connection(stream,peer.ip(),server).await;});
                }
            }
            result=tokio::signal::ctrl_c()=>{result?;break;}
            _=terminate.recv()=>break,
        }
    }
    Ok(())
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid hexadecimal bytes".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}

pub(super) async fn call(address: &str, request: GatewayRequest) -> Result<Value> {
    let address: SocketAddr = address.parse()?;
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err("gateway client requires a loopback address and nonzero port".into());
    }
    let mut stream =
        tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(address)).await??;
    let bytes = serde_json::to_vec(&request)?;
    if bytes.len() > MAX_FRAME {
        return Err("gateway request exceeds byte limit".into());
    }
    let response = tokio::time::timeout(Duration::from_secs(42), async {
        write_frame(&mut stream, &bytes, MAX_FRAME).await?;
        let response = read_frame(&mut stream, MAX_RESPONSE).await?;
        Ok::<Value, Box<dyn std::error::Error + Send + Sync>>(serde_json::from_slice(&response)?)
    })
    .await??;
    if let Some(error) = response.get("error").and_then(Value::as_str) {
        return Err(error.to_owned().into());
    }
    Ok(response)
}

pub(super) async fn run(args: &[String]) -> Result<()> {
    match args {
        [command, genesis, socket, address] if command == "serve" => {
            serve(Path::new(genesis), Path::new(socket), address.parse()?).await
        }
        [command, address, output] if command == "genesis" => {
            let response = call(
                address,
                GatewayRequest::Context {
                    account: "00".repeat(32),
                },
            )
            .await?;
            let bytes = decode_hex(
                response["genesis_bytes"]
                    .as_str()
                    .ok_or("missing gateway genesis bytes")?,
            )?;
            let genesis = Genesis::decode(&bytes)?;
            if response["genesis"] != files::hex(genesis.id().as_bytes()) {
                return Err("gateway genesis identity mismatch".into());
            }
            files::create_or_match(Path::new(output), &bytes, false)?;
            println!("{}", json!({"status":"genesis_saved","genesis":response["genesis"],"path":output}));
            Ok(())
        }
        [command, address, account] if command == "context" => {
            let response = call(
                address,
                GatewayRequest::Context {
                    account: account.clone(),
                },
            )
            .await?;
            println!("{response}");
            Ok(())
        }
        [command, address, id] if command == "receipt" => {
            let _: [u8; 32] = files::unhex(id)?;
            let response = call(address, GatewayRequest::Receipt { id: id.clone() }).await?;
            println!("{response}");
            Ok(())
        }
        [command, address, genesis_path, action] if command == "submit" => {
            let genesis = Genesis::decode(&files::read(Path::new(genesis_path), 128 * 1024, false)?)?;
            let bytes = files::read(
                Path::new(action),
                genesis.profile().limits().record_bytes as usize,
                true,
            )?;
            let signed = SignedOperation::decode(&bytes)?;
            signed.verify_signature(&genesis)?;
            let response = call(
                address,
                GatewayRequest::Submit {
                    bytes: files::hex(&bytes),
                },
            )
            .await?;
            if response["operation"] != files::hex(signed.id().as_bytes()) {
                return Err("gateway returned different operation identity".into());
            }
            if !matches!(
                response["result"]["status"].as_str(),
                Some("transported" | "finalized")
            ) {
                return Err("gateway returned an invalid action acknowledgement".into());
            }
            println!("{response}");
            Ok(())
        }
        _ => Err("usage: gateway serve GENESIS CONTROL_SOCKET LOOPBACK_IP:PORT; gateway genesis ADDRESS OUTPUT; gateway context ADDRESS ACCOUNT; gateway submit ADDRESS GENESIS ACTION; gateway receipt ADDRESS OPERATION_ID".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_caller_author_and_global_windows() {
        let mut limits = Limits::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..CALLER_REQUESTS {
            assert!(limits.caller(ip));
        }
        assert!(!limits.caller(ip));
        let author = AccountId::from_bytes([7; 32]);
        for _ in 0..AUTHOR_SUBMITS {
            assert!(limits.author(author));
        }
        assert!(!limits.author(author));
        for n in 1..8 {
            let ip = IpAddr::V6((n as u128).into());
            for _ in 0..CALLER_REQUESTS {
                assert!(limits.caller(ip));
            }
        }
        assert!(!limits.caller("127.0.0.2".parse().unwrap()));
        limits.since = Instant::now() - WINDOW;
        for n in 0..256u16 {
            let ip = IpAddr::V6((n as u128 + 1).into());
            assert!(limits.caller(ip));
            let mut bytes = [0u8; 32];
            bytes[..2].copy_from_slice(&n.to_be_bytes());
            assert!(limits.author(AccountId::from_bytes(bytes)));
        }
        assert!(!limits.caller("127.0.0.2".parse().unwrap()));
        assert!(!limits.author(AccountId::from_bytes([255; 32])));
        limits.since = Instant::now() - WINDOW;
        assert!(limits.caller(ip));
        assert!(limits.author(author));
    }

    #[test]
    fn request_shape_is_strict() {
        assert!(
            serde_json::from_slice::<GatewayRequest>(
                br#"{"command":"receipt","id":"abc","extra":1}"#
            )
            .is_err()
        );
        assert!(serde_json::from_slice::<GatewayRequest>(br#"{"command":"shutdown"}"#).is_err());
        assert!(decode_hex("a").is_err());
        assert!(decode_hex("zz").is_err());
    }

    #[tokio::test]
    async fn client_and_listener_refuse_cleartext_non_loopback_addresses() {
        let request = GatewayRequest::Receipt {
            id: "00".repeat(32),
        };
        assert!(
            call("192.0.2.1:45800", request)
                .await
                .unwrap_err()
                .to_string()
                .contains("loopback")
        );
        assert!(
            serve(
                Path::new("missing-genesis"),
                Path::new("missing-socket"),
                "0.0.0.0:45800".parse().unwrap()
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("loopback")
        );
    }
}
