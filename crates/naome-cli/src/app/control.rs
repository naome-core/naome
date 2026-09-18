use super::{Result, setup::NodeConfig};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

pub const MAXIMUM: usize = 3 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Status,
    Shutdown,
    Submit { bytes: String },
    Receipt { id: String },
    Question { id: String },
    History { height: u64 },
    Proof { id: String },
    StartProofFetch { validator: usize, id: String },
    ProofFetch { validator: usize, id: String },
    SetPeer { validator: usize, enabled: bool },
}
pub async fn read(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let length = stream.read_u32().await? as usize;
    if length > MAXIMUM {
        return Err("control frame exceeds its byte limit".into());
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}
pub async fn write(stream: &mut UnixStream, bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAXIMUM {
        return Err("control response exceeds its byte limit".into());
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(bytes).await?;
    Ok(())
}
pub async fn call(config: &NodeConfig, request: Request) -> Result<Value> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut stream = UnixStream::connect(&config.control_socket).await?;
        if stream.peer_cred()?.uid() != rustix::process::geteuid().as_raw() {
            return Err("control server belongs to another user".into());
        }
        write(&mut stream, &serde_json::to_vec(&request)?).await?;
        let value: Value = serde_json::from_slice(&read(&mut stream).await?)?;
        if let Some(error) = value.get("error").and_then(Value::as_str) {
            return Err(error.to_owned().into());
        }
        Ok(value)
    })
    .await
    .map_err(
        |_| "node control request timed out; operation may still finalize, query its receipt",
    )?
}
pub(crate) use crate::archive::status;
