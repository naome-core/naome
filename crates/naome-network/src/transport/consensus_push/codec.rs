use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{StreamProtocol, request_response};

use super::{
    CONSENSUS_PUSH_VOTE_BYTES, ConsensusPushMessage, ConsensusPushReceipt, ConsensusPushRequest,
    ConsensusPushSize,
};
use crate::transport::inbound_retention::InboundRetentionBudget;

pub(in crate::transport) const CONSENSUS_PUSH_PROTOCOL: StreamProtocol =
    StreamProtocol::new("/naome/fixed-validator-consensus-push-v0");
const PROPOSAL_TAG: u8 = 0;
const VOTE_TAG: u8 = 1;

#[derive(Clone)]
pub(in crate::transport) struct ConsensusPushCodec {
    inbound_budget: Arc<InboundRetentionBudget>,
}
impl ConsensusPushCodec {
    pub(in crate::transport) const fn new(inbound_budget: Arc<InboundRetentionBudget>) -> Self {
        Self { inbound_budget }
    }
}

async fn read_body<T: AsyncRead + Unpin + Send>(io: &mut T, length: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
    bytes.resize(length, 0);
    io.read_exact(&mut bytes).await?;
    Ok(bytes)
}

#[async_trait]
impl request_response::Codec for ConsensusPushCodec {
    type Protocol = StreamProtocol;
    type Request = ConsensusPushRequest;
    type Response = ConsensusPushReceipt;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut tag = [0; 1];
        io.read_exact(&mut tag).await?;
        let size = match tag[0] {
            PROPOSAL_TAG => {
                let mut lengths = [0; 8];
                io.read_exact(&mut lengths).await?;
                ConsensusPushSize::Proposal {
                    control_bytes: u32::from_be_bytes(lengths[..4].try_into().expect("four bytes"))
                        as usize,
                    payload_bytes: u32::from_be_bytes(lengths[4..].try_into().expect("four bytes"))
                        as usize,
                }
            }
            VOTE_TAG => ConsensusPushSize::Vote {
                bytes: CONSENSUS_PUSH_VOTE_BYTES,
            },
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unknown consensus push tag",
                ));
            }
        };
        // Validate BOTH proposal lengths and reserve their combined custody before
        // reading or allocating either body. The inner encodings stay opaque.
        size.validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let permit = InboundRetentionBudget::try_acquire(&self.inbound_budget, size.body_bytes())
            .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                "inbound consensus retention budget exhausted",
            )
        })?;
        let message = match size {
            ConsensusPushSize::Proposal {
                control_bytes,
                payload_bytes,
            } => ConsensusPushMessage::Proposal {
                canonical_proposal: read_body(io, control_bytes).await?,
                canonical_artifact: read_body(io, payload_bytes).await?,
            },
            ConsensusPushSize::Vote { bytes } => ConsensusPushMessage::Vote {
                canonical_vote: read_body(io, bytes).await?,
            },
        };
        crate::transport::codec::require_eof(io, "consensus push has trailing bytes").await?;
        Ok(ConsensusPushRequest::from_inbound(message, permit))
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut receipt = [0; 1];
        io.read_exact(&mut receipt).await?;
        if receipt != [1] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid consensus push receipt",
            ));
        }
        crate::transport::codec::require_eof(io, "consensus push receipt has trailing bytes")
            .await?;
        Ok(ConsensusPushReceipt)
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        request
            .message
            .size()
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        match request.message() {
            ConsensusPushMessage::Proposal {
                canonical_proposal,
                canonical_artifact,
            } => {
                let control_length = u32::try_from(canonical_proposal.len())
                    .expect("validated proposal length fits u32");
                let payload_length = u32::try_from(canonical_artifact.len())
                    .expect("validated payload length fits u32");
                io.write_all(&[PROPOSAL_TAG]).await?;
                io.write_all(&control_length.to_be_bytes()).await?;
                io.write_all(&payload_length.to_be_bytes()).await?;
                io.write_all(canonical_proposal).await?;
                io.write_all(canonical_artifact).await
            }
            ConsensusPushMessage::Vote { canonical_vote } => {
                io.write_all(&[VOTE_TAG]).await?;
                io.write_all(canonical_vote).await
            }
        }
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        _: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&[1]).await
    }
}

#[cfg(test)]
mod tests;
