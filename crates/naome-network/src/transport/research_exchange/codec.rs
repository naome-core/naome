use super::{
    Custody, RESEARCH_FRAME_HEADER_BYTES, ResearchContext, ResearchRequest, ResearchResponse,
    WireRequest, WireResponse, research_frame_length,
};
use crate::transport::inbound_retention::InboundRetentionBudget;
use async_trait::async_trait;
use libp2p::{
    StreamProtocol,
    futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    request_response,
};
use std::{io, sync::Arc};
pub(in crate::transport) const RESEARCH_PROTOCOL: StreamProtocol =
    StreamProtocol::new("/naome/research-mvp-v1");
#[derive(Clone)]
pub(in crate::transport) struct ResearchCodec {
    pub(super) context: Option<ResearchContext>,
    pub(super) maximum: usize,
    pub(super) global: Option<Arc<InboundRetentionBudget>>,
    pub(super) requests: Arc<InboundRetentionBudget>,
    pub(super) responses: Arc<InboundRetentionBudget>,
}
impl ResearchCodec {
    async fn read<T: AsyncRead + Unpin + Send>(
        &self,
        io: &mut T,
        response: bool,
    ) -> io::Result<(Vec<u8>, Arc<Custody>)> {
        let context = self
            .context
            .ok_or_else(|| io::Error::other("research disabled"))?;
        let mut header = [0; RESEARCH_FRAME_HEADER_BYTES];
        io.read_exact(&mut header).await?;
        let length =
            research_frame_length(&header, response, context, self.maximum).map_err(invalid)?;
        // Two frame charges cover decode's temporary buffer and retained Arc payloads.
        let global = InboundRetentionBudget::try_acquire(
            self.global.as_ref().expect("enabled research budget"),
            2 * length,
        )
        .ok_or_else(capacity)?;
        let peer = InboundRetentionBudget::try_acquire(
            if response {
                &self.responses
            } else {
                &self.requests
            },
            2 * length,
        )
        .ok_or_else(capacity)?;
        let custody = Arc::new(Custody {
            _global: global,
            peer: Some(peer),
        });
        let mut bytes = vec![0; length];
        bytes[..RESEARCH_FRAME_HEADER_BYTES].copy_from_slice(&header);
        io.read_exact(&mut bytes[RESEARCH_FRAME_HEADER_BYTES..])
            .await?;
        crate::transport::codec::require_eof(io, "research trailing bytes").await?;
        Ok((bytes, custody))
    }
}
fn invalid(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
fn capacity() -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, "research custody capacity")
}
#[async_trait]
impl request_response::Codec for ResearchCodec {
    type Protocol = StreamProtocol;
    type Request = WireRequest;
    type Response = WireResponse;
    async fn read_request<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request> {
        let (bytes, custody) = self.read(io, false).await?;
        let request =
            ResearchRequest::from_wire_bytes(&bytes, self.context.expect("enabled"), self.maximum)
                .map_err(invalid)?;
        Ok(WireRequest { request, custody })
    }
    async fn read_response<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response> {
        let (bytes, custody) = self.read(io, true).await?;
        let response =
            ResearchResponse::from_wire_bytes(&bytes, self.context.expect("enabled"), self.maximum)
                .map_err(invalid)?;
        Ok(WireResponse {
            response,
            _custody: custody,
        })
    }
    async fn write_request<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()> {
        io.write_all(&request.request.to_wire_bytes()).await
    }
    async fn write_response<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()> {
        io.write_all(&response.response.to_wire_bytes()).await
    }
}
