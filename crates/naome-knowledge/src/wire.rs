use crate::{Envelope, object::Metadata};
use libp2p::{
    StreamProtocol,
    futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    request_response,
};
use serde::{Deserialize, Serialize};
use std::{io, sync::Arc};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

mod program;

pub(crate) const PROTOCOL: StreamProtocol = StreamProtocol::new("/naome/knowledge");
pub(crate) const TOPIC: &str = "naome-knowledge";
const BINARY_PROGRAM: u32 = 1 << 31;
pub(crate) const FRAME_CONTRACT: &str =
    "naome:frames:json-control,binary-program,binary-defined-formula-question";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Message {
    pub compatibility: [u8; 32],
    pub body: Body,
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(Clone))]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum Body {
    Inventory {
        known: Option<[u8; 32]>,
        after: Option<crate::corpus::InventoryCursor>,
        limit: usize,
    },
    Describe {
        id: [u8; 32],
    },
    Get {
        root: [u8; 32],
        id: [u8; 32],
    },
    Offer {
        metadata: Metadata,
    },
    InventoryUnchanged {
        root: [u8; 32],
    },
    InventoryResult {
        snapshot: crate::corpus::InventorySnapshot,
        ids: Vec<[u8; 32]>,
        next: Option<crate::corpus::InventoryCursor>,
    },
    InventoryRestart,
    Description {
        metadata: Metadata,
    },
    Object {
        root: [u8; 32],
        object: Envelope,
    },
    #[serde(skip)]
    ProgramDescription {
        root: Option<[u8; 32]>,
        metadata: crate::object::ProgramMetadata,
    },
    #[serde(skip)]
    ProgramOffer {
        metadata: crate::object::ProgramMetadata,
    },
    ProgramGet {
        root: [u8; 32],
        id: [u8; 32],
        start: u64,
        limit: usize,
    },
    #[serde(skip)]
    ProgramData {
        root: [u8; 32],
        id: [u8; 32],
        chunk: naome_proof::program::Chunk,
    },
    Missing,
    Receipt {
        status: String,
    },
    Error {
        reason: String,
    },
}

#[derive(Debug)]
pub(crate) struct Frame {
    pub message: Message,
    // Across all connections, retain only the configured inbound working set.
    _permit: Option<OwnedSemaphorePermit>,
    _memory: Option<Arc<crate::resources::MemoryLease>>,
}

impl Frame {
    pub fn new(body: Body) -> Self {
        Self {
            message: Message {
                compatibility: crate::compatibility(),
                body,
            },
            _permit: None,
            _memory: None,
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
            budget: Arc::new(Semaphore::new(
                crate::resources::active_limits().inbound_frames,
            )),
        }
    }
}

impl Codec {
    async fn read<T: AsyncRead + Unpin + Send>(&self, stream: &mut T) -> io::Result<Frame> {
        let mut header = [0; 4];
        stream.read_exact(&mut header).await?;
        let header = u32::from_be_bytes(header);
        let binary = header & BINARY_PROGRAM != 0;
        let length = (header & !BINARY_PROGRAM) as usize;
        if length > frame_limit() {
            return Err(invalid("frame byte limit"));
        }
        let permit = self
            .budget
            .clone()
            .try_acquire_owned()
            .map_err(|_| invalid("frame capacity"))?;
        let commands = if binary {
            // Every instruction occupies at least two bytes on the wire.
            (length / 2).min(naome_proof::program::CHUNK_RECORDS)
                * 2
                * std::mem::size_of::<naome_proof::program::Command>()
        } else {
            0
        };
        let memory = frame_memory(length, commands, binary)?;
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes).await?;
        let mut trailing = [0];
        if stream.read(&mut trailing).await? != 0 {
            return Err(invalid("trailing frame bytes"));
        }
        let message: Message = if binary {
            program::decode(&bytes).map_err(invalid)?
        } else {
            serde_json::from_slice(&bytes).map_err(invalid)?
        };
        Ok(Frame {
            message,
            _permit: Some(permit),
            _memory: Some(memory),
        })
    }

    async fn write<T: AsyncWrite + Unpin + Send>(
        &self,
        stream: &mut T,
        frame: Frame,
    ) -> io::Result<()> {
        let _memory = crate::resources::MemoryLease::acquire(frame_limit()).map_err(invalid)?;
        let binary = program::binary(&frame.message.body);
        let bytes = if binary {
            program::encode(&frame.message).map_err(invalid)?
        } else {
            let mut output = BoundedOutput(Vec::new());
            serde_json::to_writer(&mut output, &frame.message).map_err(invalid)?;
            output.0
        };
        if bytes.len() > frame_limit() {
            return Err(invalid("frame byte limit"));
        }
        let header = (bytes.len() as u32) | if binary { BINARY_PROGRAM } else { 0 };
        stream.write_all(&header.to_be_bytes()).await?;
        stream.write_all(&bytes).await?;
        stream.close().await
    }
}

fn frame_memory(
    length: usize,
    commands: usize,
    binary: bool,
) -> io::Result<Arc<crate::resources::MemoryLease>> {
    crate::resources::MemoryLease::acquire(
        length
            .checked_mul(if binary { 16 } else { 4 })
            .and_then(|bytes| bytes.checked_add(commands))
            .ok_or_else(|| invalid("frame memory overflow"))?,
    )
    .map_err(invalid)
}

fn frame_limit() -> usize {
    2 * crate::resources::limits().proof_bytes + 1024
}

struct BoundedOutput(Vec<u8>);
impl std::io::Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > frame_limit().saturating_sub(self.0.len()) {
            return Err(invalid("frame byte limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn invalid(error: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

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
mod tests;
