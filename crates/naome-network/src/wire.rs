//! Length-prefixed REP exchange. The length is checked before allocating.
use libp2p::{
    StreamProtocol,
    futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    request_response,
};
use naome_protocol::{
    store::{Packet, Snapshot, sharing::MAX_MEMBER_BYTES},
    wire::Id,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::io;

pub const PROTOCOL: StreamProtocol = StreamProtocol::new("/naome/rep/archive/1");
pub const TOPIC: &str = "naome-rep-releases-v1";
const MAX_REQUEST: usize = 512;
const MAX_RESPONSE: usize = 2 * MAX_MEMBER_BYTES + 512;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Heads,
    Manifest { head: Id },
    Object { head: Id, id: Id },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Heads(Vec<Id>),
    Manifest(Snapshot),
    Object(Packet),
    Unavailable,
    Busy,
}

#[derive(Clone, Default)]
pub struct Codec;

async fn read<V: DeserializeOwned>(
    stream: &mut (impl AsyncRead + Unpin),
    max: usize,
) -> io::Result<V> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid frame length",
        ));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

async fn write<V: Serialize>(
    stream: &mut (impl AsyncWrite + Unpin),
    value: V,
    max: usize,
) -> io::Result<()> {
    let bytes = serde_json::to_vec(&value)?;
    if bytes.len() > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds budget",
        ));
    }
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(&bytes).await?;
    stream.close().await
}

impl request_response::Codec for Codec {
    type Protocol = StreamProtocol;
    type Request = Request;
    type Response = Response;
    async fn read_request<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &StreamProtocol,
        stream: &mut T,
    ) -> io::Result<Request> {
        read(stream, MAX_REQUEST).await
    }
    async fn read_response<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &StreamProtocol,
        stream: &mut T,
    ) -> io::Result<Response> {
        read(stream, MAX_RESPONSE).await
    }
    async fn write_request<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &StreamProtocol,
        stream: &mut T,
        value: Request,
    ) -> io::Result<()> {
        write(stream, value, MAX_REQUEST).await
    }
    async fn write_response<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &StreamProtocol,
        stream: &mut T,
        value: Response,
    ) -> io::Result<()> {
        write(stream, value, MAX_RESPONSE).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::futures::io::Cursor;

    #[tokio::test]
    async fn invalid_lengths_and_truncation_do_not_decode() {
        for length in [0, MAX_REQUEST as u32 + 1, u32::MAX, 3] {
            let mut stream = Cursor::new(length.to_be_bytes());
            assert!(read::<Request>(&mut stream, MAX_REQUEST).await.is_err());
        }
    }
}
