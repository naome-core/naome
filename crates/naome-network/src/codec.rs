use std::io;

use async_trait::async_trait;
use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{StreamProtocol, request_response};
use naome::proof_exchange::{
    PROOF_REQUEST_BYTES, PROOF_RESPONSE_MAX_BYTES, ProofRequest, ProofResponse,
};

pub(super) const PROTOCOL: StreamProtocol = StreamProtocol::new("/naome/proof-exchange");

#[derive(Clone)]
pub(super) struct ProofCodec;

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
