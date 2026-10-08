use crate::{Envelope, object::Metadata, store::MAX_ENVELOPE_BYTES};
use async_trait::async_trait;
use libp2p::{
    StreamProtocol,
    futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    request_response,
};
use serde::{Deserialize, Serialize};
use std::{io, sync::Arc};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub(crate) const INVENTORY_PAGE: usize = 64;
pub(crate) const MAX_FRAME: usize = MAX_ENVELOPE_BYTES + 512;
pub(crate) const PROTOCOL: StreamProtocol = StreamProtocol::new("/naome/knowledge/2");

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Message {
    pub compatibility: [u8; 32],
    pub body: Body,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum Body {
    Inventory { after: Option<[u8; 32]> },
    Describe { id: [u8; 32] },
    Get { root: [u8; 32], id: [u8; 32] },
    Offer { metadata: Metadata },
    InventoryResult { ids: Vec<[u8; 32]> },
    Description { metadata: Metadata },
    Object { root: [u8; 32], object: Envelope },
    Missing,
    Receipt { status: String },
    Error { reason: String },
}

#[derive(Debug)]
pub(crate) struct Frame {
    pub message: Message,
    // Across all connections, retain at most 32 decoded inbound frames.
    _permit: Option<OwnedSemaphorePermit>,
}

impl Frame {
    pub fn new(body: Body) -> Self {
        Self {
            message: Message {
                compatibility: crate::compatibility(),
                body,
            },
            _permit: None,
        }
    }
}

#[derive(Clone)]
pub(crate) struct Codec {
    budget: Arc<Semaphore>,
}
impl Default for Codec {
    fn default() -> Self {
        Self {
            budget: Arc::new(Semaphore::new(32)),
        }
    }
}

impl Codec {
    async fn read<T: AsyncRead + Unpin + Send>(&self, stream: &mut T) -> io::Result<Frame> {
        let mut header = [0; 4];
        stream.read_exact(&mut header).await?;
        let length = u32::from_be_bytes(header) as usize;
        if length > MAX_FRAME {
            return Err(invalid("frame byte limit"));
        }
        let permit = self
            .budget
            .clone()
            .try_acquire_owned()
            .map_err(|_| invalid("frame capacity"))?;
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes).await?;
        let mut trailing = [0];
        if stream.read(&mut trailing).await? != 0 {
            return Err(invalid("trailing frame bytes"));
        }
        let message = serde_json::from_slice(&bytes).map_err(invalid)?;
        Ok(Frame {
            message,
            _permit: Some(permit),
        })
    }

    async fn write<T: AsyncWrite + Unpin + Send>(
        &self,
        stream: &mut T,
        frame: Frame,
    ) -> io::Result<()> {
        let bytes = serde_json::to_vec(&frame.message).map_err(invalid)?;
        if bytes.len() > MAX_FRAME {
            return Err(invalid("frame byte limit"));
        }
        stream
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .await?;
        stream.write_all(&bytes).await?;
        stream.close().await
    }
}

fn invalid(error: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[async_trait]
impl request_response::Codec for Codec {
    type Protocol = StreamProtocol;
    type Request = Frame;
    type Response = Frame;
    async fn read_request<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &StreamProtocol,
        stream: &mut T,
    ) -> io::Result<Frame> {
        self.read(stream).await
    }
    async fn read_response<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &StreamProtocol,
        stream: &mut T,
    ) -> io::Result<Frame> {
        self.read(stream).await
    }
    async fn write_request<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &StreamProtocol,
        stream: &mut T,
        frame: Frame,
    ) -> io::Result<()> {
        self.write(stream, frame).await
    }
    async fn write_response<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &StreamProtocol,
        stream: &mut T,
        frame: Frame,
    ) -> io::Result<()> {
        self.write(stream, frame).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::futures::io::Cursor;

    fn encoded() -> Vec<u8> {
        let bytes =
            serde_json::to_vec(&Frame::new(Body::Inventory { after: None }).message).unwrap();
        let mut framed = (bytes.len() as u32).to_be_bytes().to_vec();
        framed.extend(bytes);
        framed
    }

    #[test]
    fn v2_rejects_legacy_payload_offers_unknown_metadata_and_unbound_gets() {
        let envelope = serde_json::json!({"compatibility":"00".repeat(32),"proof_id":"00".repeat(32),"statement_id":"00".repeat(32),"proof":"00"});
        for body in [
            serde_json::json!({"kind":"Offer","object":envelope}),
            serde_json::json!({"kind":"Get","id":vec![0u8;32]}),
            serde_json::json!({"kind":"Offer","metadata":{"proof_id":"00".repeat(32),"statement_id":"00".repeat(32),"question":"goal = all(x,eq(x,x))","proof":"00"}}),
        ] {
            assert!(
                serde_json::from_value::<Message>(
                    serde_json::json!({"compatibility":crate::compatibility(),"body":body})
                )
                .is_err()
            );
        }
        assert_eq!(PROTOCOL.as_ref(), "/naome/knowledge/2");
    }

    #[tokio::test]
    async fn strict_frames_reject_oversize_trailing_and_truncation() {
        let codec = Codec::default();
        assert!(codec.read(&mut Cursor::new(encoded())).await.is_ok());
        let mut trailing = encoded();
        trailing.push(0);
        assert!(
            codec
                .read(&mut Cursor::new(trailing))
                .await
                .unwrap_err()
                .to_string()
                .contains("trailing")
        );
        let mut truncated = encoded();
        truncated.pop();
        assert!(codec.read(&mut Cursor::new(truncated)).await.is_err());
        let header = (MAX_FRAME as u32 + 1).to_be_bytes().to_vec();
        assert!(
            codec
                .read(&mut Cursor::new(header))
                .await
                .unwrap_err()
                .to_string()
                .contains("byte limit")
        );
    }

    #[tokio::test]
    async fn frame_custody_is_shared_and_released_after_handling() {
        let codec = Codec::default();
        let other = codec.clone();
        let mut retained = Vec::new();
        for _ in 0..32 {
            retained.push(codec.read(&mut Cursor::new(encoded())).await.unwrap());
        }
        assert!(
            other
                .read(&mut Cursor::new(encoded()))
                .await
                .unwrap_err()
                .to_string()
                .contains("capacity")
        );
        retained.pop();
        assert!(other.read(&mut Cursor::new(encoded())).await.is_ok());
    }
}
