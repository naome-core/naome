use std::io;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{StreamProtocol, request_response};
use naome_protocol::artifact_exchange::{
    ARTIFACT_REQUEST_BYTES, ARTIFACT_RESPONSE_MAX_BYTES, ArtifactRequest, ArtifactResponse,
};
use naome_protocol::block_exchange::{
    ARTIFACT_BLOCK_REQUEST_BYTES, ARTIFACT_BLOCK_RESPONSE_MAX_BYTES, ArtifactBlockRequest,
};
use naome_protocol::chain_head_announcement::{
    ARTIFACT_CHAIN_HEAD_ANNOUNCEMENT_BYTES, ArtifactChainHeadAnnouncement,
};
use naome_protocol::chain_head_exchange::{
    ARTIFACT_CHAIN_HEAD_REQUEST_BYTES, ARTIFACT_CHAIN_HEAD_RESPONSE_BYTES,
    ArtifactChainHeadExchangeWireError, ArtifactChainHeadRequest, ArtifactChainHeadResponse,
};

use crate::address_store::MAX_SIGNED_PEER_RECORD_BYTES;
use crate::record_exchange::{
    MAX_PEER_RECORDS_PER_BATCH, PeerRecordBatch, PeerRecordExchangeWireError, PeerRecordPullRequest,
};
use crate::recovery_bundle_push::{
    RECOVERY_BUNDLE_PUSH_MAX_BYTES, RecoveryBundlePushInboundBudget, RecoveryBundlePushReceipt,
    RecoveryBundlePushRequest,
};

pub(super) const ARTIFACT_PROTOCOL: StreamProtocol =
    StreamProtocol::new("/naome/artifact-exchange");
pub(super) const ARTIFACT_BLOCK_PROTOCOL: StreamProtocol =
    StreamProtocol::new("/naome/artifact-block-exchange");
pub(super) const ARTIFACT_CHAIN_HEAD_PROTOCOL: StreamProtocol =
    StreamProtocol::new("/naome/artifact-chain-head-exchange");
pub(super) const ARTIFACT_CHAIN_HEAD_ANNOUNCEMENT_PROTOCOL: StreamProtocol =
    StreamProtocol::new("/naome/artifact-chain-head-announcement");
pub(super) const PEER_RECORD_PROTOCOL: StreamProtocol =
    StreamProtocol::new("/naome/peer-record-exchange");
pub(super) const RECOVERY_BUNDLE_PUSH_PROTOCOL: StreamProtocol =
    StreamProtocol::new("/naome/recovery-bundle-push-v0");

#[derive(Clone)]
pub(super) struct ArtifactCodec;

#[derive(Clone)]
pub(super) struct ArtifactBlockCodec;

#[derive(Clone)]
pub(super) struct ArtifactChainHeadCodec;

#[derive(Clone)]
pub(super) struct ArtifactChainHeadAnnouncementCodec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ArtifactChainHeadAnnouncementReceipt;

const ARTIFACT_CHAIN_HEAD_ANNOUNCEMENT_RECEIPT: u8 = 0x01;

#[derive(Clone)]
pub(super) struct PeerRecordCodec;

#[derive(Clone)]
pub(super) struct PeerRecordResponderCodec;
#[derive(Clone)]
pub(super) struct RecoveryBundlePushCodec {
    inbound_budget: Arc<RecoveryBundlePushInboundBudget>,
}

impl RecoveryBundlePushCodec {
    pub(super) const fn new(inbound_budget: Arc<RecoveryBundlePushInboundBudget>) -> Self {
        Self { inbound_budget }
    }
}

#[derive(Debug)]
pub(super) enum PeerRecordResponderRequest {
    Valid,
    Invalid,
    ReadTimedOut,
    ReadFailed(io::Error),
}

const RESPONDER_REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub(super) struct ArtifactBlockWireResponse {
    bytes: [u8; ARTIFACT_BLOCK_RESPONSE_MAX_BYTES],
    length: u8,
}

impl ArtifactBlockWireResponse {
    pub(super) const fn unavailable() -> Self {
        Self {
            bytes: [0; ARTIFACT_BLOCK_RESPONSE_MAX_BYTES],
            length: 0,
        }
    }

    pub(super) fn from_block_bytes(bytes: [u8; ARTIFACT_BLOCK_RESPONSE_MAX_BYTES]) -> Self {
        Self {
            bytes,
            length: u8::try_from(ARTIFACT_BLOCK_RESPONSE_MAX_BYTES)
                .expect("the fixed artifact-block response length fits u8"),
        }
    }

    #[cfg(test)]
    pub(super) fn new(bytes: impl AsRef<[u8]>) -> Self {
        let bytes = bytes.as_ref();
        assert!(
            bytes.len() <= ARTIFACT_BLOCK_RESPONSE_MAX_BYTES,
            "artifact-block wire response exceeds its fixed buffer"
        );
        let mut response = Self::with_length(bytes.len());
        response.as_bytes_mut().copy_from_slice(bytes);
        response
    }

    fn with_length(length: usize) -> Self {
        debug_assert!(length <= ARTIFACT_BLOCK_RESPONSE_MAX_BYTES);
        Self {
            bytes: [0; ARTIFACT_BLOCK_RESPONSE_MAX_BYTES],
            length: u8::try_from(length).expect("the artifact-block response length fits u8"),
        }
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.length)]
    }

    fn as_bytes_mut(&mut self) -> &mut [u8] {
        let length = usize::from(self.length);
        &mut self.bytes[..length]
    }
}

#[async_trait]
impl request_response::Codec for ArtifactCodec {
    type Protocol = StreamProtocol;
    type Request = ArtifactRequest;
    type Response = ArtifactResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut bytes = [0_u8; ARTIFACT_REQUEST_BYTES];
        io.read_exact(&mut bytes).await?;
        require_eof(io, "artifact request has trailing bytes").await?;
        ArtifactRequest::from_wire_bytes(&bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut length_bytes = [0_u8; size_of::<u32>()];
        io.read_exact(&mut length_bytes).await?;
        let length = u32::from_be_bytes(length_bytes) as usize;
        if length > ARTIFACT_RESPONSE_MAX_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "artifact response length {length} exceeds maximum {ARTIFACT_RESPONSE_MAX_BYTES}"
                ),
            ));
        }

        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        bytes.resize(length, 0);
        io.read_exact(&mut bytes).await?;
        require_eof(io, "artifact response has trailing bytes").await?;
        ArtifactResponse::from_wire_bytes(bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&request.to_wire_bytes()).await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = response.into_wire_bytes();
        let length = u32::try_from(bytes.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "artifact response length does not fit u32",
            )
        })?;
        io.write_all(&length.to_be_bytes()).await?;
        io.write_all(&bytes).await
    }
}

#[async_trait]
impl request_response::Codec for ArtifactBlockCodec {
    type Protocol = StreamProtocol;
    type Request = ArtifactBlockRequest;
    type Response = ArtifactBlockWireResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut bytes = [0_u8; ARTIFACT_BLOCK_REQUEST_BYTES];
        io.read_exact(&mut bytes).await?;
        require_eof(io, "artifact-block request has trailing bytes").await?;
        ArtifactBlockRequest::from_wire_bytes(&bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut length = [0_u8; 1];
        io.read_exact(&mut length).await?;
        let length = usize::from(length[0]);
        if length > ARTIFACT_BLOCK_RESPONSE_MAX_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "artifact-block response length {length} exceeds maximum \
                     {ARTIFACT_BLOCK_RESPONSE_MAX_BYTES}"
                ),
            ));
        }

        let mut response = ArtifactBlockWireResponse::with_length(length);
        io.read_exact(response.as_bytes_mut()).await?;
        require_eof(io, "artifact-block response has trailing bytes").await?;
        Ok(response)
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&request.to_wire_bytes()).await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = response.as_bytes();
        let length =
            u8::try_from(bytes.len()).expect("the fixed artifact-block response length fits u8");
        io.write_all(&[length]).await?;
        io.write_all(bytes).await
    }
}

#[async_trait]
impl request_response::Codec for ArtifactChainHeadCodec {
    type Protocol = StreamProtocol;
    type Request = ArtifactChainHeadRequest;
    type Response = ArtifactChainHeadResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut bytes = [0_u8; ARTIFACT_CHAIN_HEAD_REQUEST_BYTES];
        io.read_exact(&mut bytes).await?;
        require_eof(io, "artifact-chain-head request has trailing bytes").await?;
        ArtifactChainHeadRequest::from_wire_bytes(&bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut length = [0_u8; 1];
        io.read_exact(&mut length).await?;
        let length = usize::from(length[0]);
        if length != 0 && length != ARTIFACT_CHAIN_HEAD_RESPONSE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                ArtifactChainHeadExchangeWireError::InvalidResponseLength { actual: length },
            ));
        }
        let mut bytes = [0_u8; ARTIFACT_CHAIN_HEAD_RESPONSE_BYTES];
        io.read_exact(&mut bytes[..length]).await?;
        require_eof(io, "artifact-chain-head response has trailing bytes").await?;
        ArtifactChainHeadResponse::from_wire_bytes(&bytes[..length])
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&request.to_wire_bytes()).await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        match response.to_wire_bytes() {
            Some(bytes) => {
                let mut frame = [0_u8; 1 + ARTIFACT_CHAIN_HEAD_RESPONSE_BYTES];
                frame[0] = u8::try_from(ARTIFACT_CHAIN_HEAD_RESPONSE_BYTES)
                    .expect("the chain-head response length fits u8");
                frame[1..].copy_from_slice(&bytes);
                io.write_all(&frame).await
            }
            None => io.write_all(&[0]).await,
        }
    }
}

#[async_trait]
impl request_response::Codec for ArtifactChainHeadAnnouncementCodec {
    type Protocol = StreamProtocol;
    type Request = ArtifactChainHeadAnnouncement;
    type Response = ArtifactChainHeadAnnouncementReceipt;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut bytes = [0_u8; ARTIFACT_CHAIN_HEAD_ANNOUNCEMENT_BYTES];
        io.read_exact(&mut bytes).await?;
        require_eof(io, "artifact-chain-head announcement has trailing bytes").await?;
        ArtifactChainHeadAnnouncement::from_wire_bytes(&bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut receipt = [0_u8; 1];
        io.read_exact(&mut receipt).await?;
        if receipt[0] != ARTIFACT_CHAIN_HEAD_ANNOUNCEMENT_RECEIPT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "artifact-chain-head announcement receipt is not 0x01",
            ));
        }
        require_eof(
            io,
            "artifact-chain-head announcement receipt has trailing bytes",
        )
        .await?;
        Ok(ArtifactChainHeadAnnouncementReceipt)
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        announcement: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&announcement.to_wire_bytes()).await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        _receipt: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&[ARTIFACT_CHAIN_HEAD_ANNOUNCEMENT_RECEIPT])
            .await
    }
}

#[async_trait]
impl request_response::Codec for PeerRecordCodec {
    type Protocol = StreamProtocol;
    type Request = PeerRecordPullRequest;
    type Response = PeerRecordBatch;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        require_eof(io, "peer-record pull request has trailing bytes").await?;
        Ok(PeerRecordPullRequest)
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut count = [0_u8; 1];
        io.read_exact(&mut count).await?;
        let count = usize::from(count[0]);
        if count > MAX_PEER_RECORDS_PER_BATCH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                PeerRecordExchangeWireError::RecordCount {
                    actual: count,
                    maximum: MAX_PEER_RECORDS_PER_BATCH,
                },
            ));
        }

        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(1 + count * size_of::<u16>())
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        bytes.push(u8::try_from(count).expect("the peer-record batch count fits u8"));
        for index in 0..count {
            let mut length_bytes = [0_u8; size_of::<u16>()];
            io.read_exact(&mut length_bytes).await?;
            let length = usize::from(u16::from_be_bytes(length_bytes));
            if length == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    PeerRecordExchangeWireError::EmptyRecord { index },
                ));
            }
            if length > MAX_SIGNED_PEER_RECORD_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    PeerRecordExchangeWireError::RecordTooLong {
                        index,
                        actual: length,
                        maximum: MAX_SIGNED_PEER_RECORD_BYTES,
                    },
                ));
            }
            bytes
                .try_reserve(length_bytes.len() + length)
                .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
            bytes.extend_from_slice(&length_bytes);
            let start = bytes.len();
            bytes.resize(start + length, 0);
            io.read_exact(&mut bytes[start..]).await?;
        }
        require_eof(io, "peer-record batch has trailing bytes").await?;
        PeerRecordBatch::from_wire_bytes(&bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        _io: &mut T,
        _request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = response
            .to_wire_bytes()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        io.write_all(&bytes).await
    }
}

#[async_trait]
impl request_response::Codec for PeerRecordResponderCodec {
    type Protocol = StreamProtocol;
    type Request = PeerRecordResponderRequest;
    type Response = Arc<Vec<u8>>;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut trailing = [0_u8; 1];
        match tokio::time::timeout(RESPONDER_REQUEST_READ_TIMEOUT, io.read(&mut trailing)).await {
            Ok(Ok(0)) => Ok(PeerRecordResponderRequest::Valid),
            Ok(Ok(_)) => Ok(PeerRecordResponderRequest::Invalid),
            Ok(Err(source)) => Ok(PeerRecordResponderRequest::ReadFailed(source)),
            Err(_) => Ok(PeerRecordResponderRequest::ReadTimedOut),
        }
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        _io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the inbound-only peer-record responder cannot read responses",
        ))
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        _io: &mut T,
        _request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the inbound-only peer-record responder cannot write requests",
        ))
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&response).await
    }
}

async fn require_eof<T>(io: &mut T, message: &'static str) -> io::Result<()>
where
    T: AsyncRead + Unpin + Send,
{
    let mut trailing = [0_u8; 1];
    if io.read(&mut trailing).await? == 0 {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidData, message))
    }
}

#[async_trait]
impl request_response::Codec for RecoveryBundlePushCodec {
    type Protocol = StreamProtocol;
    type Request = RecoveryBundlePushRequest;
    type Response = RecoveryBundlePushReceipt;
    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut length = [0; 4];
        io.read_exact(&mut length).await?;
        let length = u32::from_be_bytes(length) as usize;
        if length > RECOVERY_BUNDLE_PUSH_MAX_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "recovery-bundle request exceeds maximum",
            ));
        }
        let permit = RecoveryBundlePushInboundBudget::try_acquire(&self.inbound_budget, length)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "inbound recovery-bundle retention budget exhausted",
                )
            })?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        bytes.resize(length, 0);
        io.read_exact(&mut bytes).await?;
        require_eof(io, "recovery-bundle request has trailing bytes").await?;
        Ok(RecoveryBundlePushRequest::from_inbound(bytes, permit))
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
        require_eof(io, "recovery-bundle receipt has trailing bytes").await?;
        if receipt == [1] {
            Ok(RecoveryBundlePushReceipt)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid recovery-bundle receipt",
            ))
        }
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
        let bytes = request.into_bundle_bytes();
        let length = u32::try_from(bytes.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "recovery-bundle request length does not fit u32",
            )
        })?;
        io.write_all(&length.to_be_bytes()).await?;
        io.write_all(&bytes).await
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
