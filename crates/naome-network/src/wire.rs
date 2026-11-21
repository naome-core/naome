//! Length-prefixed REP exchange. Object bodies contain the exact archive bytes.
use libp2p::{
    StreamProtocol,
    futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    request_response,
};
use naome_protocol::{
    store::{
        Snapshot,
        sharing::{MAX_MEMBER_BYTES, Member},
    },
    wire::{Format, Id},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::io;

pub const PROTOCOL: StreamProtocol = StreamProtocol::new("/naome/rep/archive/2");
pub const TOPIC: &str = "naome-rep-releases-v2";
const MAX_REQUEST: usize = 512;
const MAX_CONTROL: usize = 65_536;
const LENGTH_BYTES: usize = 4;
const BLOB_ACCESS_BYTES: usize = 32;

const UNAVAILABLE: u8 = 0;
const BUSY: u8 = 1;
const HEADS: u8 = 2;
const MANIFEST: u8 = 3;
const RECORD_A: u8 = 4;
const RECORD_B: u8 = 5;
const BLOB: u8 = 6;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Heads,
    Manifest { head: Id },
    Object { head: Id, id: Id },
}
#[derive(Debug)]
pub enum Response {
    Heads(Vec<Id>),
    Manifest(Snapshot),
    Object(Member),
    Unavailable,
    Busy,
}

#[derive(Clone, Default)]
pub struct Codec {
    pub trace_object_frames: bool,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

async fn length(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<usize> {
    let mut header = [0; LENGTH_BYTES];
    stream.read_exact(&mut header).await?;
    Ok(u32::from_be_bytes(header) as usize)
}

async fn payload(
    stream: &mut (impl AsyncRead + Unpin),
    size: usize,
    max: usize,
) -> io::Result<Vec<u8>> {
    if size > max {
        return Err(invalid("frame exceeds budget"));
    }
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

fn json<V: DeserializeOwned>(bytes: &[u8]) -> io::Result<V> {
    serde_json::from_slice(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

async fn read_response(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Response> {
    let size = length(stream)
        .await?
        .checked_sub(1)
        .ok_or_else(|| invalid("missing response tag"))?;
    let mut tag = [0];
    stream.read_exact(&mut tag).await?;
    Ok(match tag[0] {
        UNAVAILABLE if size == 0 => Response::Unavailable,
        BUSY if size == 0 => Response::Busy,
        HEADS => Response::Heads(json(&payload(stream, size, MAX_CONTROL).await?)?),
        MANIFEST => Response::Manifest(json(&payload(stream, size, MAX_CONTROL).await?)?),
        tag @ (RECORD_A | RECORD_B) if size != 0 => {
            let format = if tag == RECORD_A {
                Format::A
            } else {
                Format::B
            };
            let bytes = payload(stream, size, MAX_MEMBER_BYTES).await?;
            Response::Object(Member {
                id: Id::record(format, &bytes),
                blob_access: None,
                bytes,
            })
        }
        BLOB => {
            let size = size
                .checked_sub(BLOB_ACCESS_BYTES)
                .filter(|n| *n <= MAX_MEMBER_BYTES)
                .ok_or_else(|| invalid("invalid blob length"))?;
            let mut digest = [0; BLOB_ACCESS_BYTES];
            stream.read_exact(&mut digest).await?;
            let bytes = payload(stream, size, MAX_MEMBER_BYTES).await?;
            Response::Object(Member {
                id: Id::blob(&bytes),
                blob_access: Some(Id::from_blob_digest(digest)),
                bytes,
            })
        }
        _ => return Err(invalid("invalid response tag or size")),
    })
}

/// Count the bytes delivered to the negotiated stream after successful writes.
async fn write_frame(
    stream: &mut (impl AsyncWrite + Unpin),
    chunks: &[&[u8]],
) -> io::Result<usize> {
    let size = chunks.iter().map(|chunk| chunk.len()).sum::<usize>();
    let header = u32::try_from(size)
        .map_err(|_| invalid("frame exceeds length field"))?
        .to_be_bytes();
    stream.write_all(&header).await?;
    for chunk in chunks {
        stream.write_all(chunk).await?;
    }
    stream.close().await?;
    Ok(header.len() + size)
}

async fn write_json(
    stream: &mut (impl AsyncWrite + Unpin),
    prefix: &[u8],
    value: impl Serialize,
    max: usize,
) -> io::Result<()> {
    let bytes = serde_json::to_vec(&value)?;
    if bytes.len() > max {
        return Err(invalid("frame exceeds budget"));
    }
    write_frame(stream, &[prefix, &bytes]).await?;
    Ok(())
}

async fn write_object(
    stream: &mut (impl AsyncWrite + Unpin),
    member: &Member,
) -> io::Result<usize> {
    if member.bytes.len() > MAX_MEMBER_BYTES {
        return Err(invalid("object exceeds budget"));
    }
    match (member.id.format(), member.blob_access) {
        (Some(format), None) => {
            let tag = match format {
                Format::A => RECORD_A,
                Format::B => RECORD_B,
            };
            write_frame(stream, &[&[tag], &member.bytes]).await
        }
        (None, Some(access)) => {
            let digest = access
                .blob_digest()
                .ok_or_else(|| invalid("invalid blob access identifier"))?;
            write_frame(stream, &[&[BLOB], &digest, &member.bytes]).await
        }
        _ => Err(invalid("invalid object access metadata")),
    }
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
        let size = length(stream).await?;
        json(&payload(stream, size, MAX_REQUEST).await?)
    }
    async fn read_response<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &StreamProtocol,
        stream: &mut T,
    ) -> io::Result<Response> {
        read_response(stream).await
    }
    async fn write_request<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &StreamProtocol,
        stream: &mut T,
        value: Request,
    ) -> io::Result<()> {
        write_json(stream, &[], value, MAX_REQUEST).await
    }
    async fn write_response<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &StreamProtocol,
        stream: &mut T,
        value: Response,
    ) -> io::Result<()> {
        match value {
            Response::Heads(ids) => write_json(stream, &[HEADS], ids, MAX_CONTROL).await?,
            Response::Manifest(snapshot) => {
                write_json(stream, &[MANIFEST], snapshot, MAX_CONTROL).await?
            }
            Response::Unavailable => {
                write_frame(stream, &[&[UNAVAILABLE]]).await?;
            }
            Response::Busy => {
                write_frame(stream, &[&[BUSY]]).await?;
            }
            Response::Object(member) => {
                let frame_bytes = write_object(stream, &member).await?;
                if self.trace_object_frames {
                    println!(
                        "{}",
                        serde_json::json!({"object_frame":member.id,"object_bytes":member.bytes.len(),"frame_bytes":frame_bytes})
                    );
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::{futures::io::Cursor, request_response::Codec as _};

    #[tokio::test]
    async fn invalid_lengths_and_truncation_do_not_decode() {
        for length in [0, MAX_REQUEST as u32 + 1, u32::MAX, 3] {
            let mut stream = Cursor::new(length.to_be_bytes());
            assert!(
                Codec::default()
                    .read_request(&PROTOCOL, &mut stream)
                    .await
                    .is_err()
            );
        }
        for (tag, size) in [
            (BLOB, 0),
            (BLOB, MAX_MEMBER_BYTES + 33),
            (RECORD_A, MAX_MEMBER_BYTES + 1),
            (RECORD_A, 3),
            (UNAVAILABLE, 2),
            (u8::MAX, 0),
        ] {
            let mut frame = ((size + 1) as u32).to_be_bytes().to_vec();
            frame.push(tag);
            assert!(read_response(&mut Cursor::new(frame)).await.is_err());
        }
    }

    #[tokio::test]
    async fn blob_metadata_and_exact_binary_bytes_round_trip() -> io::Result<()> {
        let access = Id::blob(naome_protocol::profile::READ_ONLY);
        for bytes in [vec![], vec![0, 255, 0, 42]] {
            let id = Id::blob(&bytes);
            let mut out = Cursor::new(Vec::new());
            let size = write_object(
                &mut out,
                &Member {
                    id,
                    blob_access: Some(access),
                    bytes: bytes.clone(),
                },
            )
            .await?;
            assert_eq!(size, LENGTH_BYTES + 1 + BLOB_ACCESS_BYTES + bytes.len());
            assert_eq!(out.get_ref().len(), size);
            let Response::Object(object) =
                read_response(&mut Cursor::new(out.into_inner())).await?
            else {
                panic!("expected blob response");
            };
            assert_eq!(object.id, id);
            assert_eq!(object.blob_access, Some(access));
            assert_eq!(object.bytes, bytes);
        }
        Ok(())
    }
}
