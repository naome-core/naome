use super::{Result, files, setup::NodeConfig};
use naome_research::ResearchState;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
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
pub fn status(state: &ResearchState) -> Value {
    let active=state.active().map(|a|json!({"submission":files::hex(a.submission.as_bytes()),"question":files::hex(a.question.as_bytes()),"family":files::hex(a.family.as_bytes()),"attempt":a.number,"phase":format!("{:?}",a.phase),"deadline":a.deadline,"round":a.solution_round.map(|r|files::hex(r.as_bytes())),"votes":a.votes.iter().map(|(id,yes)|json!({"owner":files::hex(id.as_bytes()),"yes":yes})).collect::<Vec<_>>(),"commitments":a.commitments,"reveals":a.reveals}));
    json!({"status":"finalized","genesis":files::hex(state.genesis().id().as_bytes()),"profile":files::hex(state.genesis().profile().id().as_bytes()),"height":state.height(),"head":files::hex(state.head().as_bytes()),"state":files::hex(state.commitment().as_bytes()),"time":state.time(),"active":active,"library_root":files::hex(&state.library().root()),"proof_count":state.library().len(),"queued":state.queued().count(),"accounts":state.balances().accounts().iter().map(|(id,balance)|json!({"account":files::hex(id.as_bytes()),"balance_atoms":balance.to_string(),"next_nonce":state.next_nonce(*id)})).collect::<Vec<_>>(),"validators":state.genesis().validators().iter().enumerate().map(|(i,v)|json!({"index":i,"owner":files::hex(v.owner.as_bytes()),"endpoint":v.endpoint})).collect::<Vec<_>>(),"reserve_atoms":state.balances().reserve().to_string(),"paid_completions":state.balances().paid_completions(),"claims":state.claims().values().map(|c|json!({"family":files::hex(c.family.as_bytes()),"author":files::hex(c.author.as_bytes()),"ordinal":c.completion_ordinal})).collect::<Vec<_>>(),"remaining_records":state.remaining_records(),"reserved_records":state.reserved_records(),"remaining_bytes":state.remaining_bytes(),"reserved_bytes":state.reserved_bytes(),"terminated":state.terminated()})
}
