use async_trait::async_trait;
use libp2p::{
    StreamProtocol,
    futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
};
use naome_consensus::verified_membership::{
    MembershipApproval, MembershipFinalityProof, MembershipMachineEvent, MembershipRequest,
};
use std::{borrow::Cow, io};

use super::*;

pub(super) const PROTOCOL: StreamProtocol = StreamProtocol::new("/naome/verified-membership/0");
pub(super) const MAX_FRAME_BYTES: usize = MembershipMachineEvent::MAX_BYTES;

pub(super) struct RequestFrame {
    pub message: MembershipRequestMessage,
    pub permit: Option<InboundRetentionPermit>,
}
pub(super) struct ResponseFrame {
    pub message: MembershipResponseMessage,
    pub _permit: Option<InboundRetentionPermit>,
}
impl fmt::Debug for RequestFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (tag, bytes) = request_body(&self.message);
        f.debug_struct("MembershipRequestFrame")
            .field("tag", &tag)
            .field("bytes", &bytes.len())
            .finish()
    }
}
impl fmt::Debug for ResponseFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (tag, bytes) = response_body(&self.message);
        f.debug_struct("MembershipResponseFrame")
            .field("tag", &tag)
            .field("bytes", &bytes.len())
            .finish()
    }
}
pub(super) struct MembershipCodec {
    lanes: Arc<DecodeLanes>,
    peer: Option<PeerId>,
}
impl Clone for MembershipCodec {
    fn clone(&self) -> Self {
        Self {
            lanes: Arc::clone(&self.lanes),
            peer: self
                .peer
                .or_else(|| self.lanes.factory_peer.read().ok().and_then(|peer| *peer)),
        }
    }
}
impl MembershipCodec {
    pub fn new(lanes: Arc<DecodeLanes>) -> Self {
        Self { lanes, peer: None }
    }
    fn budget(&self) -> io::Result<Arc<InboundRetentionBudget>> {
        self.lanes.budget(
            self.peer
                .ok_or_else(|| io::Error::other("unbound membership codec"))?,
        )
    }
}

fn request_body(message: &MembershipRequestMessage) -> (u8, Cow<'_, [u8]>) {
    match message {
        MembershipRequestMessage::Publication(bytes) => (0, Cow::Borrowed(bytes)),
        MembershipRequestMessage::Application(bytes) => (1, Cow::Borrowed(bytes)),
        MembershipRequestMessage::Approval(bytes) => (2, Cow::Borrowed(bytes)),
        MembershipRequestMessage::Candidate(bytes) => (5, Cow::Borrowed(bytes)),
        MembershipRequestMessage::Status { context } => (3, Cow::Borrowed(context)),
        MembershipRequestMessage::Finality { context, height } => {
            let mut bytes = context.to_vec();
            bytes.extend_from_slice(&height.to_be_bytes());
            (4, Cow::Owned(bytes))
        }
    }
}
fn response_body(message: &MembershipResponseMessage) -> (u8, Cow<'_, [u8]>) {
    match message {
        MembershipResponseMessage::Receipt => (0, Cow::Borrowed(&[])),
        MembershipResponseMessage::Status {
            context,
            height,
            ancestry,
        } => {
            let mut bytes = context.to_vec();
            bytes.extend_from_slice(&height.to_be_bytes());
            bytes.extend_from_slice(ancestry);
            (1, Cow::Owned(bytes))
        }
        MembershipResponseMessage::Finality(bytes) => (2, Cow::Borrowed(bytes)),
        MembershipResponseMessage::Unavailable => (3, Cow::Borrowed(&[])),
    }
}
pub(super) fn response_length(message: &MembershipResponseMessage) -> usize {
    response_body(message).1.len()
}
fn validate_shape(tag: u8, length: usize, request: bool) -> io::Result<()> {
    let valid = if request {
        match tag {
            0 => (1..=MembershipMachineEvent::MAX_BYTES).contains(&length),
            1 => (1..=MembershipRequest::MAX_BYTES).contains(&length),
            2 => (1..=MembershipApproval::MAX_BYTES).contains(&length),
            3 => length == 32,
            4 => length == 40,
            5 => (1..=naome_consensus::verified_membership::MAX_ARTIFACT_BYTES + 256)
                .contains(&length),
            _ => false,
        }
    } else {
        match tag {
            0 | 3 => length == 0,
            1 => length == 72,
            2 => (1..=MembershipFinalityProof::MAX_BYTES).contains(&length),
            _ => false,
        }
    };
    if valid {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "membership frame shape",
        ))
    }
}
pub(super) fn validate_request(message: &MembershipRequestMessage) -> io::Result<()> {
    let (tag, bytes) = request_body(message);
    validate_shape(tag, bytes.len(), true)
}
pub(super) fn validate_response(message: &MembershipResponseMessage) -> io::Result<()> {
    let (tag, bytes) = response_body(message);
    validate_shape(tag, bytes.len(), false)
}

async fn read_frame<T: AsyncRead + Unpin + Send>(
    stream: &mut T,
    request: bool,
    budget: &Arc<InboundRetentionBudget>,
) -> io::Result<(u8, Vec<u8>, InboundRetentionPermit)> {
    let mut header = [0; 5];
    stream.read_exact(&mut header).await?;
    let tag = header[0];
    let length = u32::from_be_bytes(header[1..].try_into().expect("fixed length")) as usize;
    validate_shape(tag, length, request)?;
    let permit = InboundRetentionBudget::try_acquire(budget, length)
        .ok_or_else(|| io::Error::new(io::ErrorKind::OutOfMemory, "membership retention limit"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
    bytes.resize(length, 0);
    stream.read_exact(&mut bytes).await?;
    super::super::super::codec::require_eof(stream, "membership frame trailing bytes").await?;
    Ok((tag, bytes, permit))
}
async fn write_frame<T: AsyncWrite + Unpin + Send>(
    stream: &mut T,
    tag: u8,
    bytes: &[u8],
    request: bool,
) -> io::Result<()> {
    validate_shape(tag, bytes.len(), request)?;
    stream.write_all(&[tag]).await?;
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(bytes).await
}

#[async_trait]
impl request_response::Codec for MembershipCodec {
    type Protocol = StreamProtocol;
    type Request = RequestFrame;
    type Response = ResponseFrame;
    async fn read_request<T>(
        &mut self,
        _: &Self::Protocol,
        stream: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let (tag, bytes, permit) = read_frame(stream, true, &self.budget()?).await?;
        let message = match tag {
            0 => MembershipRequestMessage::Publication(bytes),
            1 => MembershipRequestMessage::Application(bytes),
            2 => MembershipRequestMessage::Approval(bytes),
            3 => MembershipRequestMessage::Status {
                context: bytes.as_slice().try_into().expect("validated status width"),
            },
            4 => MembershipRequestMessage::Finality {
                context: bytes[..32].try_into().expect("validated context width"),
                height: u64::from_be_bytes(bytes[32..].try_into().expect("validated height width")),
            },
            5 => MembershipRequestMessage::Candidate(bytes),
            _ => unreachable!("shape validation rejects unknown tags"),
        };
        Ok(RequestFrame {
            message,
            permit: Some(permit),
        })
    }
    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        stream: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let (tag, bytes, permit) = read_frame(stream, false, &self.budget()?).await?;
        let message = match tag {
            0 => MembershipResponseMessage::Receipt,
            1 => MembershipResponseMessage::Status {
                context: bytes[..32].try_into().expect("validated context width"),
                height: u64::from_be_bytes(
                    bytes[32..40].try_into().expect("validated height width"),
                ),
                ancestry: bytes[40..].try_into().expect("validated ancestry width"),
            },
            2 => MembershipResponseMessage::Finality(bytes),
            3 => MembershipResponseMessage::Unavailable,
            _ => unreachable!("shape validation rejects unknown tags"),
        };
        Ok(ResponseFrame {
            message,
            _permit: Some(permit),
        })
    }
    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        stream: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let (tag, bytes) = request_body(&request.message);
        write_frame(stream, tag, &bytes, true).await
    }
    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        stream: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let (tag, bytes) = response_body(&response.message);
        write_frame(stream, tag, &bytes, false).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::futures::{executor::block_on, io::Cursor, task::noop_waker_ref};
    use libp2p::request_response::Codec;
    use std::{
        future::Future,
        pin::Pin,
        sync::RwLock,
        task::{Context, Poll},
    };

    struct Stalled {
        header: Cursor<Vec<u8>>,
    }
    impl AsyncRead for Stalled {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            bytes: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            if self.header.position() == self.header.get_ref().len() as u64 {
                return Poll::Pending;
            }
            Pin::new(&mut self.header).poll_read(context, bytes)
        }
    }
    fn lanes(validator: PeerId) -> Arc<DecodeLanes> {
        Arc::new(DecodeLanes {
            admitted: RwLock::new(HashSet::from([validator])),
            factory_peer: RwLock::new(None),
            validators: Arc::new(InboundRetentionBudget::new(8, 8 * MAX_FRAME_BYTES)),
            observers: Arc::new(InboundRetentionBudget::new(2, 2 * MAX_FRAME_BYTES)),
        })
    }
    fn bound(lanes: &Arc<DecodeLanes>, peer: PeerId) -> MembershipCodec {
        let root = MembershipCodec::new(Arc::clone(lanes));
        *lanes.factory_peer.write().unwrap() = Some(peer);
        let codec = root.clone();
        *lanes.factory_peer.write().unwrap() = None;
        codec.clone()
    }
    fn status_frame() -> Cursor<Vec<u8>> {
        let mut frame = vec![3, 0, 0, 0, 32];
        frame.extend_from_slice(&[7; 32]);
        Cursor::new(frame)
    }

    #[test]
    fn stalled_observers_cannot_consume_validator_decode_capacity() {
        let validator = Keypair::generate_ed25519().public().to_peer_id();
        let observer = Keypair::generate_ed25519().public().to_peer_id();
        let lanes = lanes(validator);
        let mut first = bound(&lanes, observer);
        let mut second = first.clone();
        let mut a = Stalled {
            header: Cursor::new(vec![3, 0, 0, 0, 32]),
        };
        let mut b = Stalled {
            header: Cursor::new(vec![3, 0, 0, 0, 32]),
        };
        let protocol = PROTOCOL;
        let mut pending_a = Box::pin(first.read_request(&protocol, &mut a));
        let mut pending_b = Box::pin(second.read_request(&protocol, &mut b));
        let mut context = Context::from_waker(noop_waker_ref());
        assert!(pending_a.as_mut().poll(&mut context).is_pending());
        assert!(pending_b.as_mut().poll(&mut context).is_pending());
        assert!(
            block_on(bound(&lanes, observer).read_request(&PROTOCOL, &mut status_frame())).is_err()
        );
        let frame = block_on(bound(&lanes, validator).read_request(&PROTOCOL, &mut status_frame()))
            .unwrap();
        assert_eq!(
            frame.message,
            MembershipRequestMessage::Status { context: [7; 32] }
        );
        drop(frame);
        lanes.admitted.write().unwrap().clear();
        assert!(
            block_on(bound(&lanes, validator).read_request(&PROTOCOL, &mut status_frame()))
                .is_err()
        );
        drop(pending_a);
        drop(pending_b);
        assert!(
            block_on(bound(&lanes, observer).read_request(&PROTOCOL, &mut status_frame())).is_ok()
        );
    }

    #[test]
    fn unbound_oversized_wrong_role_and_trailing_frames_are_refused() {
        let validator = Keypair::generate_ed25519().public().to_peer_id();
        let lanes = lanes(validator);
        assert!(
            block_on(
                MembershipCodec::new(Arc::clone(&lanes))
                    .read_request(&PROTOCOL, &mut status_frame())
            )
            .is_err()
        );
        for bytes in [
            vec![255, 0, 0, 0, 0],
            vec![0, 255, 255, 255, 255],
            vec![3, 0, 0, 0, 31],
        ] {
            assert!(
                block_on(bound(&lanes, validator).read_request(&PROTOCOL, &mut Cursor::new(bytes)))
                    .is_err()
            );
        }
        let mut bytes = status_frame().into_inner();
        bytes.push(0);
        assert!(
            block_on(bound(&lanes, validator).read_request(&PROTOCOL, &mut Cursor::new(bytes)))
                .is_err()
        );
        assert!(
            block_on(bound(&lanes, validator).read_response(&PROTOCOL, &mut status_frame()))
                .is_err()
        );
        assert!(
            block_on(bound(&lanes, validator).read_request(&PROTOCOL, &mut status_frame())).is_ok()
        );
    }
}
