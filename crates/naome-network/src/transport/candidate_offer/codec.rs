use super::{CANDIDATE_OFFER_MAX_IDS, CandidateOffer, OfferRequest};
use crate::transport::inbound_retention::InboundRetentionBudget;
use async_trait::async_trait;
use libp2p::{
    StreamProtocol,
    futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    request_response,
};
use std::{io, sync::Arc};

pub(in crate::transport) const CANDIDATE_OFFER_PROTOCOL: StreamProtocol =
    StreamProtocol::new("/naome/candidate-offer-v0");
#[derive(Clone)]
pub(in crate::transport) struct CandidateOfferCodec {
    budget: Arc<InboundRetentionBudget>,
}
impl CandidateOfferCodec {
    pub(in crate::transport) fn new(budget: Arc<InboundRetentionBudget>) -> Self {
        Self { budget }
    }
}
#[async_trait]
impl request_response::Codec for CandidateOfferCodec {
    type Protocol = StreamProtocol;
    type Request = OfferRequest;
    type Response = [u8; 32];
    async fn read_request<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request> {
        let mut header = [0; 33];
        io.read_exact(&mut header).await?;
        let count = usize::from(header[32]);
        if count > CANDIDATE_OFFER_MAX_IDS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "candidate offer count",
            ));
        }
        let length = 33 + count * 32;
        let permit =
            InboundRetentionBudget::try_acquire(&self.budget, length).ok_or_else(|| {
                io::Error::new(io::ErrorKind::OutOfMemory, "candidate offer retention")
            })?;
        let mut bytes = vec![0; length];
        bytes[..33].copy_from_slice(&header);
        io.read_exact(&mut bytes[33..]).await?;
        crate::transport::codec::require_eof(io, "candidate offer trailing bytes").await?;
        let offer = CandidateOffer::from_wire_bytes(&bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        Ok(OfferRequest {
            offer,
            permit: Some(permit),
        })
    }
    async fn read_response<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response> {
        let mut digest = [0; 32];
        io.read_exact(&mut digest).await?;
        crate::transport::codec::require_eof(io, "candidate receipt trailing bytes").await?;
        Ok(digest)
    }
    async fn write_request<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()> {
        io.write_all(&request.offer.to_wire_bytes()).await
    }
    async fn write_response<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        digest: Self::Response,
    ) -> io::Result<()> {
        io.write_all(&digest).await
    }
}
