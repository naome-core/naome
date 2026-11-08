use crate::{
    Envelope,
    object::Metadata,
    outcome::{OfferStatus, PeerFailure, WireFailure},
};
use libp2p::{
    StreamProtocol,
    futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    request_response,
};
use serde::{Deserialize, Serialize};
use std::{io, sync::Arc};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

mod artifact;

pub(crate) const PROTOCOL: StreamProtocol = StreamProtocol::new("/naome/knowledge");
pub(crate) const TOPIC: &str = "naome-knowledge";
const BINARY_ARTIFACT: u32 = 1 << 31;
pub(crate) const FRAME_CONTRACT: &str =
    "naome:frames:numeric-control,packed-binary-artifact,defined-question-per-proof";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Message {
    pub compatibility: [u8; 32],
    pub body: Body,
}

fn required_field<'de, D: serde::Deserializer<'de>, T: serde::Deserialize<'de>>(
    deserializer: D,
) -> Result<T, D::Error> {
    T::deserialize(deserializer)
}

// The same declaration owns the payload schema and its numeric message kind.
macro_rules! bodies {
    (
        controls { $( $variant:ident => $kind:ident { $( $field:ident: $ty:ty ),* $(,)? } ),+ $(,)? }
        units { $( $unit:ident => $unit_kind:ident ),+ $(,)? }
        binary { $( $binary:ident => $binary_kind:ident { $( $binary_field:ident: $binary_ty:ty ),+ $(,)? } ),+ $(,)? }
    ) => {
        #[derive(Debug)]
        #[cfg_attr(test, derive(Clone))]
        pub(crate) enum Body {
            $( $variant { $( $field: $ty ),* }, )+
            $( $unit, )+
            $( $binary { $( $binary_field: $binary_ty ),+ }, )+
        }

        impl Body {
            pub(crate) fn kind(&self) -> crate::outcome::MessageKind {
                match self {
                    $( Self::$variant { .. } => crate::outcome::MessageKind::$kind, )+
                    $( Self::$unit => crate::outcome::MessageKind::$unit_kind, )+
                    $( Self::$binary { .. } => crate::outcome::MessageKind::$binary_kind, )+
                }
            }
        }

        impl serde::Serialize for Body {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                use serde::ser::{Error as _, SerializeTuple};
                let mut tuple = serializer.serialize_tuple(2)?;
                match self {
                    $( Self::$variant { $( $field ),* } => {
                        #[derive(serde::Serialize)]
                        struct Payload<'a> { $( $field: &'a $ty ),* }
                        tuple.serialize_element(&self.kind())?;
                        tuple.serialize_element(&Payload { $( $field ),* })?;
                    }, )+
                    $( Self::$unit => {
                        #[derive(serde::Serialize)]
                        struct Empty {}
                        tuple.serialize_element(&self.kind())?;
                        tuple.serialize_element(&Empty {})?;
                    }, )+
                    $( Self::$binary { .. } => return Err(S::Error::custom("binary body in control frame")), )+
                }
                tuple.end()
            }
        }

        impl<'de> serde::Deserialize<'de> for Body {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct BodyVisitor;
                impl<'de> serde::de::Visitor<'de> for BodyVisitor {
                    type Value = Body;
                    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        f.write_str("a numeric control body")
                    }
                    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Body, A::Error> {
                        use serde::de::Error as _;
                        let kind: crate::outcome::MessageKind = seq.next_element()?.ok_or_else(|| A::Error::invalid_length(0, &self))?;
                        let body = match kind {
                            $( crate::outcome::MessageKind::$kind => {
                                #[derive(serde::Deserialize)]
                                #[serde(deny_unknown_fields)]
                                struct Payload { $( #[serde(deserialize_with = "required_field")] $field: $ty ),* }
                                let payload: Payload = seq.next_element()?.ok_or_else(|| A::Error::invalid_length(1, &self))?;
                                Body::$variant { $( $field: payload.$field ),* }
                            }, )+
                            $( crate::outcome::MessageKind::$unit_kind => {
                                #[derive(serde::Deserialize)]
                                #[serde(deny_unknown_fields)]
                                struct Payload {}
                                let _: Payload = seq.next_element()?.ok_or_else(|| A::Error::invalid_length(1, &self))?;
                                Body::$unit
                            }, )+
                            $( crate::outcome::MessageKind::$binary_kind => return Err(A::Error::custom("binary body in control frame")), )+
                        };
                        if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                            return Err(A::Error::invalid_length(3, &self));
                        }
                        Ok(body)
                    }
                }
                deserializer.deserialize_tuple(2, BodyVisitor)
            }
        }
    };
}

bodies! {
    controls {
        Inventory => Inventory { known: Option<[u8; 32]>, after: Option<crate::corpus::InventoryCursor>, limit: usize },
        Describe => Describe { id: [u8; 32] },
        Get => Get { root: [u8; 32], id: [u8; 32] },
        Offer => Offer { metadata: Metadata },
        InventoryUnchanged => InventoryUnchanged { root: [u8; 32] },
        InventoryResult => InventoryResult { snapshot: crate::corpus::InventorySnapshot, ids: Vec<[u8; 32]>, next: Option<crate::corpus::InventoryCursor> },
        Description => Description { metadata: Metadata },
        ProgramGet => ProgramGet { root: [u8; 32], id: [u8; 32], start: u64, limit: usize },
        Receipt => Receipt { status: OfferStatus },
        Error => PeerError { code: PeerFailure },
    }
    units { InventoryRestart => InventoryRestart, Missing => Missing }
    binary {
        Object => Object { root: [u8; 32], object: Envelope, question: Option<String> },
        ProgramDescription => ProgramDescription { root: Option<[u8; 32]>, metadata: crate::object::ProgramMetadata },
        ProgramOffer => ProgramOffer { metadata: crate::object::ProgramMetadata },
        ProgramData => ProgramData { root: [u8; 32], id: [u8; 32], chunk: naome_proof::program::Chunk },
    }
}

#[derive(Debug)]
pub(crate) struct Frame {
    pub message: Message,
    // Across all connections, retain only the configured inbound working set.
    _permit: Option<OwnedSemaphorePermit>,
    _memory: Option<Arc<crate::resources::MemoryLease>>,
    _expanded: Vec<Arc<crate::resources::MemoryLease>>,
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
            _expanded: Vec::new(),
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
        let binary = header & BINARY_ARTIFACT != 0;
        let length = (header & !BINARY_ARTIFACT) as usize;
        if length > frame_limit() {
            return Err(WireFailure::FrameLimit.into());
        }
        let permit = self
            .budget
            .clone()
            .try_acquire_owned()
            .map_err(|_| WireFailure::FrameCapacity)?;
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
            return Err(WireFailure::TrailingFrameBytes.into());
        }
        let (message, expanded) = if binary {
            artifact::decode(&bytes)?
        } else {
            (
                serde_json::from_slice(&bytes).map_err(|_| WireFailure::ControlRecord)?,
                Vec::new(),
            )
        };
        Ok(Frame {
            message,
            _permit: Some(permit),
            _memory: Some(memory),
            _expanded: expanded,
        })
    }

    async fn write<T: AsyncWrite + Unpin + Send>(
        &self,
        stream: &mut T,
        frame: Frame,
    ) -> io::Result<()> {
        let _memory = crate::resources::MemoryLease::acquire(frame_limit())
            .map_err(|_| WireFailure::FrameMemory)?;
        let binary = artifact::binary(&frame.message.body);
        let bytes = if binary {
            artifact::encode(&frame.message)?
        } else {
            let mut output = BoundedOutput(Vec::new());
            serde_json::to_writer(&mut output, &frame.message).map_err(|error| {
                if error.is_io() {
                    WireFailure::FrameLimit
                } else {
                    WireFailure::ControlRecord
                }
            })?;
            output.0
        };
        if bytes.len() > frame_limit() {
            return Err(WireFailure::FrameLimit.into());
        }
        let header = (bytes.len() as u32) | if binary { BINARY_ARTIFACT } else { 0 };
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
            .ok_or(WireFailure::FrameMemory)?,
    )
    .map_err(|_| WireFailure::FrameMemory.into())
}

fn frame_limit() -> usize {
    2 * (crate::resources::limits().proof_bytes + naome_checker::question::QUESTION_BYTES) + 1024
}

struct BoundedOutput(Vec<u8>);
impl std::io::Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > frame_limit().saturating_sub(self.0.len()) {
            return Err(WireFailure::FrameLimit.into());
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl std::fmt::Display for WireFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        u32::from(*self).fmt(formatter)
    }
}

impl std::error::Error for WireFailure {}

impl From<WireFailure> for io::Error {
    fn from(error: WireFailure) -> Self {
        Self::new(io::ErrorKind::InvalidData, error)
    }
}

pub(crate) fn stream_failure(error: &io::Error) -> WireFailure {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<WireFailure>())
        .copied()
        .unwrap_or(WireFailure::StreamIo)
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
