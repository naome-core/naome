use std::io;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{StreamProtocol, request_response};
use naome::block_exchange::{
    PROOF_BLOCK_REQUEST_BYTES, PROOF_BLOCK_RESPONSE_MAX_BYTES, ProofBlockRequest,
};
use naome::proof_exchange::{
    PROOF_REQUEST_BYTES, PROOF_RESPONSE_MAX_BYTES, ProofRequest, ProofResponse,
};

use crate::address_store::MAX_SIGNED_PEER_RECORD_BYTES;
use crate::record_exchange::{
    MAX_PEER_RECORDS_PER_BATCH, PeerRecordBatch, PeerRecordExchangeWireError, PeerRecordPullRequest,
};

pub(super) const PROTOCOL: StreamProtocol = StreamProtocol::new("/naome/proof-exchange");
pub(super) const PROOF_BLOCK_PROTOCOL: StreamProtocol =
    StreamProtocol::new("/naome/proof-block-exchange");
pub(super) const PEER_RECORD_PROTOCOL: StreamProtocol =
    StreamProtocol::new("/naome/peer-record-exchange");

#[derive(Clone)]
pub(super) struct ProofCodec;

#[derive(Clone)]
pub(super) struct ProofBlockCodec;

#[derive(Clone)]
pub(super) struct PeerRecordCodec;

#[derive(Clone)]
pub(super) struct PeerRecordResponderCodec;

#[derive(Debug)]
pub(super) enum PeerRecordResponderRequest {
    Valid,
    Invalid,
    ReadTimedOut,
    ReadFailed(io::Error),
}

const RESPONDER_REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub(super) struct ProofBlockWireResponse {
    bytes: Vec<u8>,
}

impl ProofBlockWireResponse {
    pub(super) fn new(bytes: Vec<u8>) -> Self {
        debug_assert!(bytes.len() <= PROOF_BLOCK_RESPONSE_MAX_BYTES);
        Self { bytes }
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[async_trait]
impl request_response::Codec for ProofCodec {
    type Protocol = StreamProtocol;
    type Request = ProofRequest;
    type Response = ProofResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut bytes = [0_u8; PROOF_REQUEST_BYTES];
        io.read_exact(&mut bytes).await?;
        require_eof(io, "proof request has trailing bytes").await?;
        ProofRequest::from_wire_bytes(&bytes)
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
        if length > PROOF_RESPONSE_MAX_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "proof response length {length} exceeds maximum {PROOF_RESPONSE_MAX_BYTES}"
                ),
            ));
        }

        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        bytes.resize(length, 0);
        io.read_exact(&mut bytes).await?;
        require_eof(io, "proof response has trailing bytes").await?;
        ProofResponse::from_wire_bytes(bytes)
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
                "proof response length does not fit u32",
            )
        })?;
        io.write_all(&length.to_be_bytes()).await?;
        io.write_all(&bytes).await
    }
}

#[async_trait]
impl request_response::Codec for ProofBlockCodec {
    type Protocol = StreamProtocol;
    type Request = ProofBlockRequest;
    type Response = ProofBlockWireResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut bytes = [0_u8; PROOF_BLOCK_REQUEST_BYTES];
        io.read_exact(&mut bytes).await?;
        require_eof(io, "proof-block request has trailing bytes").await?;
        ProofBlockRequest::from_wire_bytes(&bytes)
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
        let mut length_bytes = [0_u8; size_of::<u16>()];
        io.read_exact(&mut length_bytes).await?;
        let length = usize::from(u16::from_be_bytes(length_bytes));
        if length > PROOF_BLOCK_RESPONSE_MAX_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "proof-block response length {length} exceeds maximum \
                     {PROOF_BLOCK_RESPONSE_MAX_BYTES}"
                ),
            ));
        }

        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        bytes.resize(length, 0);
        io.read_exact(&mut bytes).await?;
        require_eof(io, "proof-block response has trailing bytes").await?;
        Ok(ProofBlockWireResponse::new(bytes))
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
        let bytes = response.into_bytes();
        if bytes.len() > PROOF_BLOCK_RESPONSE_MAX_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "proof-block response length {} exceeds maximum \
                     {PROOF_BLOCK_RESPONSE_MAX_BYTES}",
                    bytes.len()
                ),
            ));
        }
        let length = u16::try_from(bytes.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "proof-block response length does not fit u16",
            )
        })?;
        io.write_all(&length.to_be_bytes()).await?;
        io.write_all(&bytes).await
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

#[cfg(test)]
mod tests;
