use std::{io, sync::Arc};

use async_trait::async_trait;
use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{StreamProtocol, request_response};
use naome_chain::ArtifactChainId;
use naome_consensus::{
    ConsensusContextV0, ConsensusGenesisId, ConsensusHeight, ConsensusProtocolVersion,
};

use super::{
    FINALITY_PROOF_REQUEST_BYTES, FinalityProofRequest, FinalityProofResponse,
    InboundRetentionBudget, WireRequest, WireResponse, valid_lengths,
};
use crate::transport::codec::require_eof;

pub(in crate::transport) const FINALITY_PROOF_PROTOCOL: StreamProtocol =
    StreamProtocol::new("/naome/fixed-validator-finality-proof-v0");

#[derive(Clone)]
pub(in crate::transport) struct FinalityProofCodec {
    requests: Arc<InboundRetentionBudget>,
    responses: Arc<InboundRetentionBudget>,
}

impl FinalityProofCodec {
    pub(in crate::transport) fn new(
        requests: Arc<InboundRetentionBudget>,
        responses: Arc<InboundRetentionBudget>,
    ) -> Self {
        Self {
            requests,
            responses,
        }
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

async fn body<T: AsyncRead + Unpin + Send>(io: &mut T, length: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
    bytes.resize(length, 0);
    io.read_exact(&mut bytes).await?;
    Ok(bytes)
}

#[async_trait]
impl request_response::Codec for FinalityProofCodec {
    type Protocol = StreamProtocol;
    type Request = WireRequest;
    type Response = WireResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        // Even tiny retained requests keep one peer slot across timeout/reconnect.
        let permit =
            InboundRetentionBudget::try_acquire(&self.requests, FINALITY_PROOF_REQUEST_BYTES)
                .ok_or_else(|| invalid("finality request retention exhausted"))?;
        let mut bytes = [0; FINALITY_PROOF_REQUEST_BYTES];
        io.read_exact(&mut bytes).await?;
        require_eof(io, "finality request has trailing bytes").await?;
        let context = ConsensusContextV0::new(
            ArtifactChainId::from_bytes(bytes[..32].try_into().expect("chain width")),
            ConsensusGenesisId::from_bytes(bytes[32..64].try_into().expect("genesis width")),
            ConsensusProtocolVersion::new(u32::from_be_bytes(
                bytes[64..68].try_into().expect("version width"),
            )),
        );
        let height = ConsensusHeight::new(u64::from_be_bytes(
            bytes[68..].try_into().expect("height width"),
        ));
        let request = FinalityProofRequest::new(context, height)
            .ok_or_else(|| invalid("zero finality height"))?;
        Ok(WireRequest {
            request,
            permit: Some(permit),
        })
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut tag = [0];
        io.read_exact(&mut tag).await?;
        let (envelope, payload) = match tag[0] {
            0 => (0, 0),
            1 => {
                let mut lengths = [0; 8];
                io.read_exact(&mut lengths).await?;
                let envelope =
                    u32::from_be_bytes(lengths[..4].try_into().expect("length width")) as usize;
                let payload =
                    u32::from_be_bytes(lengths[4..].try_into().expect("length width")) as usize;
                if !valid_lengths(envelope, payload) {
                    return Err(invalid("finality response lengths"));
                }
                (envelope, payload)
            }
            _ => return Err(invalid("unknown finality response tag")),
        };
        // Validate BOTH lengths and reserve combined custody before allocating either body.
        let permit = InboundRetentionBudget::try_acquire(&self.responses, envelope + payload)
            .ok_or_else(|| invalid("finality response retention exhausted"))?;
        let response = if tag[0] == 0 {
            FinalityProofResponse::Unavailable
        } else {
            FinalityProofResponse::Found {
                canonical_envelope: body(io, envelope).await?,
                canonical_artifact: body(io, payload).await?,
            }
        };
        require_eof(io, "finality response has trailing bytes").await?;
        Ok(WireResponse {
            response,
            _permit: permit,
        })
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
        let mut bytes = [0; FINALITY_PROOF_REQUEST_BYTES];
        bytes[..32].copy_from_slice(request.request.context.chain_id().as_bytes());
        bytes[32..64].copy_from_slice(request.request.context.genesis_id().as_bytes());
        bytes[64..68].copy_from_slice(
            &request
                .request
                .context
                .protocol_version()
                .value()
                .to_be_bytes(),
        );
        bytes[68..].copy_from_slice(&request.request.height.value().to_be_bytes());
        io.write_all(&bytes).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        match &response.response {
            FinalityProofResponse::Unavailable => io.write_all(&[0]).await,
            FinalityProofResponse::Found {
                canonical_envelope,
                canonical_artifact,
            } => {
                if !valid_lengths(canonical_envelope.len(), canonical_artifact.len()) {
                    return Err(invalid("finality response lengths"));
                }
                io.write_all(&[1]).await?;
                io.write_all(&(canonical_envelope.len() as u32).to_be_bytes())
                    .await?;
                io.write_all(&(canonical_artifact.len() as u32).to_be_bytes())
                    .await?;
                io.write_all(canonical_envelope).await?;
                io.write_all(canonical_artifact).await
            }
        }
        // `response` keeps its custody permit until writing completes or is cancelled.
    }
}
