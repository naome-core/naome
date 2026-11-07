//! Operator-driven checkpoint exchange over the existing authenticated transport.
use super::*;
use crate::{
    frontier::Frontier,
    model_exchange::{
        Bundle, Challenge, Comparison, Profile, Registration,
        control::{Action, Request, Response},
        protocol::{self, Packet},
    },
};
use std::io::Read;
use tokio::sync::oneshot;

type ModelBook = [Option<Comparison>; 2];
const DOMAIN: &str = "naome:model-comparisons";

fn index(profile: Profile) -> usize {
    match profile {
        Profile::Solver => 0,
        Profile::Finder => 1,
    }
}

struct Hint {
    peer: String,
    comparison: Box<Comparison>,
}

impl Hint {
    fn summary(&self) -> Value {
        let registration = &self.comparison.challenge.local;
        json!({
            "peer": self.peer, "registration": registration, "model": registration.id(),
            "comparison_id": self.comparison.id(), "claimed_score": self.comparison.local,
        })
    }
}

struct Verified {
    comparison: Comparison,
    local: Arc<Bundle>,
    remote: Arc<Bundle>,
}

enum Done {
    Shared(Arc<Bundle>),
    Observed(Registration),
    Compared(Box<Verified>),
    Offered(Arc<Bundle>),
    Audited(Box<Audit>),
    Selected(Registration),
}

struct Audit {
    offer: String,
    progress: Comparison,
    complete: bool,
    sender: Arc<Bundle>,
}

struct Work {
    profile: Profile,
    cancellable: bool,
    task: tokio::task::JoinHandle<Result<Done, String>>,
}

pub(super) struct Owner {
    own: PeerId,
    signing: libp2p::identity::Keypair,
    client: crate::jobs::Client,
    computation: Arc<crate::resources::Computation>,
    outbox: mpsc::Sender<Outbound>,
    book: crate::checkpoint::Checkpoint,
    comparisons: ModelBook,
    work: Option<Work>,
    shared: [Option<Arc<Bundle>>; 2],
    verified: [Option<Box<Verified>>; 2],
    hint: [Option<Hint>; 2],
    audited: [Option<Box<Audit>>; 2],
    result: [Value; 2],
}

impl Owner {
    pub(super) fn open(
        directory: &Path,
        signing: libp2p::identity::Keypair,
        client: crate::jobs::Client,
        computation: Arc<crate::resources::Computation>,
        outbox: mpsc::Sender<Outbound>,
    ) -> Result<Self, String> {
        let own = signing.public().to_peer_id();
        let path = crate::storage::research_directory(directory)?.join("model-comparisons.sqlite3");
        let book = if path.exists() {
            crate::checkpoint::Checkpoint::open_for_replay(&path, DOMAIN)?
        } else {
            crate::checkpoint::Checkpoint::create(
                &path,
                DOMAIN,
                &[None::<Comparison>, None],
                vec![],
            )?
        };
        book.require_kinds(&[])?;
        let comparisons: ModelBook = book.header()?;
        for (slot, comparison) in comparisons.iter().enumerate() {
            if let Some(comparison) = comparison {
                comparison.validate()?;
                if comparison.challenge.verifier != own.to_string()
                    || index(comparison.challenge.local.model.profile()) != slot
                {
                    return Err("retained model comparison binding differs".into());
                }
            }
        }
        Ok(Self {
            own,
            signing,
            client,
            computation,
            outbox,
            book,
            comparisons,
            work: None,
            shared: [None, None],
            verified: [None, None],
            hint: [None, None],
            audited: [None, None],
            result: [Value::Null, Value::Null],
        })
    }

    pub(super) fn request(&mut self, peer: PeerId, packet: Packet) -> Result<Packet, String> {
        match packet {
            Packet::Inspect { profile } => {
                let shared = self.shared[index(profile)]
                    .as_ref()
                    .ok_or("model profile is not shared")?;
                Ok(Packet::Manifest {
                    registration: shared.registration.clone(),
                    chunk_limit: protocol::chunk_limit(),
                })
            }
            Packet::Chunk {
                model,
                blob,
                offset,
                length,
            } => {
                if length == 0 || length > protocol::chunk_limit() {
                    return Err("model chunk exceeds wire capacity".into());
                }
                let shared = self
                    .shared
                    .iter()
                    .flatten()
                    .find(|bundle| bundle.registration.id() == model)
                    .ok_or("shared model changed or is unavailable")?;
                let data = shared
                    .part(&blob)
                    .and_then(|data| {
                        offset
                            .checked_add(length)
                            .and_then(|end| data.get(offset..end))
                    })
                    .ok_or("model chunk outside registered blob")?;
                Ok(Packet::ChunkData {
                    model,
                    blob,
                    offset,
                    data: protocol::encode(data),
                })
            }
            Packet::Offer { comparison } => {
                comparison.validate()?;
                let scope = &comparison.challenge;
                let slot = index(scope.local.model.profile());
                if scope.verifier != peer.to_string()
                    || scope.peer != self.own.to_string()
                    || comparison.local <= comparison.remote
                    || self.shared[slot]
                        .as_ref()
                        .is_none_or(|bundle| bundle.registration != scope.remote)
                {
                    return Err("offer does not address the shared recipient model".into());
                }
                if self.hint[slot]
                    .as_ref()
                    .is_none_or(|hint| hint.comparison != comparison)
                {
                    self.audited[slot] = None;
                    self.hint[slot] = Some(Hint {
                        peer: peer.to_string(),
                        comparison,
                    });
                }
                Ok(Packet::Acknowledged)
            }
            _ => Err("unexpected model request".into()),
        }
    }

    pub(super) fn control(
        &mut self,
        request: Request,
        frontier: Option<&mut Frontier>,
    ) -> Result<Response, String> {
        match request.action {
            Action::Status => return Ok(Ok(self.status(request.profile))),
            Action::Cancel => {
                let Some(work) = &self.work else {
                    return Ok(Err("no model operation is running".into()));
                };
                if work.profile != request.profile || !work.cancellable {
                    return Ok(Err("the current model operation cannot be cancelled".into()));
                }
                if !work.task.is_finished() {
                    work.task.abort();
                }
                return Ok(Ok(json!({"state":"cancelling"})));
            }
            _ => {}
        }
        if self.work.is_some() {
            return Ok(Err("a model operation is already running".into()));
        }
        match self.start(request, frontier) {
            Ok(()) => Ok(Ok(json!({"state":"queued"}))),
            Err(error) if error.fatal() => Err(error.to_string()),
            Err(error) => Ok(Err(error.to_string())),
        }
    }

    fn status(&self, profile: Profile) -> Value {
        let slot = index(profile);
        let comparison = self.comparisons[slot].as_ref();
        json!({
            "budget": crate::model_exchange::budget(profile),
            "working": self.work.as_ref().is_some_and(|work| index(work.profile) == slot),
            "shared": self.shared[slot].as_ref().map(|b| b.registration.id()),
            "offer": self.hint[slot].as_ref().map(Hint::summary),
            "comparison_id": comparison.map(Comparison::id),
            "comparison": comparison,
            "retained_artifacts": self.verified[slot].is_some(),
            "audit": self.audited[slot].as_ref().map(|audit| json!({
                "comparison_id": audit.offer, "verified_blocks": audit.progress.blocks,
                "complete": audit.complete,
            })),
            "last_operation": self.result[slot],
        })
    }

    fn start(
        &mut self,
        request: Request,
        frontier: Option<&mut Frontier>,
    ) -> Result<(), crate::Error> {
        let profile = request.profile;
        let slot = index(profile);
        let outbox = self.outbox.clone();
        let client = self.client.clone();
        let computation = self.computation.clone();
        let own = self.own;
        let mut cancellable = true;
        let task = match request.action {
            Action::Share => {
                let snapshot = prepare_snapshot(profile, frontier.as_deref())?;
                tokio::spawn(async move { Ok(Done::Shared(snapshot.get(&client).await?)) })
            }
            Action::Peer { peer } => {
                let peer = parse_peer(own, &peer)?;
                tokio::spawn(
                    async move { Ok(Done::Observed(inspect(&outbox, peer, profile).await?.0)) },
                )
            }
            Action::Unshare => {
                self.shared[slot] = None;
                self.hint[slot] = None;
                self.audited[slot] = None;
                self.result[slot] = json!({"state":"unshared"});
                return Ok(());
            }
            Action::Audit => {
                let hint = self.hint[slot].as_ref().ok_or("no peer offer to audit")?;
                let peer = parse_peer(own, &hint.peer)?;
                let claimed = (*hint.comparison).clone();
                let offer = claimed.id();
                let recipient = self.shared[slot]
                    .as_ref()
                    .filter(|bundle| bundle.registration == claimed.challenge.remote)
                    .ok_or("the offered comparison uses a different recipient model")?
                    .clone();
                let previous = self.audited[slot]
                    .as_ref()
                    .filter(|audit| audit.offer == offer);
                if previous.is_some_and(|audit| audit.complete) {
                    return Err("peer comparison is already audited".into());
                }
                let previous = previous.map(|audit| audit.progress.clone());
                tokio::spawn(async move {
                    let (registration, width) = inspect(&outbox, peer, profile).await?;
                    if registration != claimed.challenge.local {
                        return Err("offered model is no longer shared".into());
                    }
                    let sender = Arc::new(download(&outbox, peer, registration, width).await?);
                    let lease = client.model_lease().await?;
                    let progress = crate::model_exchange::worker::compare(
                        claimed.challenge.clone(),
                        previous,
                        &sender,
                        &recipient,
                        lease,
                    )
                    .await?;
                    let complete = progress.audit_against(&claimed)?;
                    Ok(Done::Audited(Box::new(Audit {
                        offer,
                        progress,
                        complete,
                        sender,
                    })))
                })
            }
            Action::Compare { peer, expected } => {
                let peer = parse_peer(own, &peer)?;
                if let Some(id) = &expected {
                    crate::object::id_bytes(id)?;
                }
                let snapshot = prepare_snapshot(profile, frontier.as_deref())?;
                let signing = self.signing.clone();
                let audited = self.audited[slot]
                    .as_ref()
                    .map(|audit| audit.sender.clone());
                // Keep one pair of downloaded artifacts per profile.
                self.verified[slot] = None;
                tokio::spawn(async move {
                    let local = snapshot.get(&client).await?;
                    let (registration, width) = inspect(&outbox, peer, profile).await?;
                    if expected
                        .as_ref()
                        .is_some_and(|expected| registration.id() != *expected)
                    {
                        return Err("advertised checkpoint differs from requested model".into());
                    }
                    // Freeze both registrations before obtaining local entropy.
                    let challenge =
                        new_challenge(&signing, peer, local.registration.clone(), registration)?;
                    let remote = if let Some(bundle) =
                        audited.filter(|bundle| bundle.registration == challenge.remote)
                    {
                        bundle
                    } else {
                        Arc::new(download(&outbox, peer, challenge.remote.clone(), width).await?)
                    };
                    let lease = client.model_lease().await?;
                    let comparison = crate::model_exchange::worker::compare(
                        challenge, None, &local, &remote, lease,
                    )
                    .await?;
                    Ok(Done::Compared(Box::new(Verified {
                        comparison,
                        local,
                        remote,
                    })))
                })
            }
            Action::Extend => {
                let verified = self.verified[slot]
                    .as_ref()
                    .ok_or("comparison artifacts are unavailable; compare first")?;
                let previous = verified.comparison.clone();
                let local = verified.local.clone();
                let remote = verified.remote.clone();
                tokio::spawn(async move {
                    let lease = client.model_lease().await?;
                    let comparison = crate::model_exchange::worker::compare(
                        previous.challenge.clone(),
                        Some(previous),
                        &local,
                        &remote,
                        lease,
                    )
                    .await?;
                    Ok(Done::Compared(Box::new(Verified {
                        comparison,
                        local,
                        remote,
                    })))
                })
            }
            Action::Offer { peer, comparison } => {
                let peer = parse_peer(own, &peer)?;
                let verified = self.selected_comparison(slot, &comparison)?;
                let score = &verified.comparison;
                if score.local <= score.remote || score.challenge.peer != peer.to_string() {
                    return Err("offer requires a verified local improvement for this peer".into());
                }
                let local = verified.local.clone();
                let comparison = Box::new(score.clone());
                let snapshot = prepare_snapshot(profile, frontier.as_deref())?;
                tokio::spawn(async move {
                    if snapshot.get(&client).await?.registration != local.registration {
                        return Err("local model changed since comparison; compare again".into());
                    }
                    let packet = Packet::Offer { comparison };
                    match send(&outbox, peer, packet).await? {
                        Packet::Acknowledged => Ok(Done::Offered(local)),
                        _ => Err("peer did not acknowledge the offer".into()),
                    }
                })
            }
            Action::Adopt { comparison } => {
                let verified = self.selected_comparison(slot, &comparison)?;
                let score = &verified.comparison;
                if score.remote <= score.local {
                    return Err("adoption requires a verified peer improvement".into());
                }
                let expected = score.challenge.local.id();
                let candidate = Some(verified.remote.clone());
                cancellable = false;
                select(profile, frontier, client, computation, expected, candidate)?
            }
            Action::Rollback { expected } => {
                crate::object::id_bytes(&expected)?;
                cancellable = false;
                select(profile, frontier, client, computation, expected, None)?
            }
            Action::Status | Action::Cancel => unreachable!("handled before launch"),
        };
        self.work = Some(Work {
            profile,
            cancellable,
            task,
        });
        self.result[slot] = Value::Null;
        Ok(())
    }

    fn selected_comparison(&self, slot: usize, id: &str) -> Result<&Verified, crate::Error> {
        crate::object::id_bytes(id)?;
        self.verified[slot]
            .as_deref()
            .filter(|v| v.comparison.id() == id)
            .ok_or_else(|| "no locally replayed comparison for this ID".into())
    }

    pub(super) async fn completed(&mut self) -> Result<(), String> {
        if !self
            .work
            .as_ref()
            .is_some_and(|work| work.task.is_finished())
        {
            return Ok(());
        }
        let work = self.work.take().expect("finished model task");
        let slot = index(work.profile);
        let outcome = work
            .task
            .await
            .unwrap_or_else(|error| Err(error.to_string()));
        let value = match outcome {
            Ok(Done::Shared(bundle)) => {
                let id = bundle.registration.id();
                self.shared[slot] = Some(bundle);
                json!({"state":"shared","model":id})
            }
            Ok(Done::Observed(registration)) => json!({
                "state":"observed", "model":registration.id(), "registration":registration
            }),
            Ok(Done::Compared(verified)) => {
                let mut comparisons = self.comparisons.clone();
                comparisons[slot] = Some(verified.comparison.clone());
                let committed =
                    crate::resources::DiskLease::acquire(self.book.directory(), 64 * 1024)
                        .and_then(|_disk| {
                            self.book
                                .commit(&comparisons, vec![])
                                .map_err(crate::Error::from)
                        });
                match committed {
                    Ok(()) => {
                        let id = verified.comparison.id();
                        self.comparisons = comparisons;
                        self.verified[slot] = Some(verified);
                        json!({"state":"verified","comparison_id":id})
                    }
                    Err(error) if error.fatal() => return Err(error.to_string()),
                    Err(error) => json!({"state":"failed","error":error.to_string()}),
                }
            }
            Ok(Done::Offered(local)) => {
                self.shared[slot] = Some(local);
                json!({"state":"offered"})
            }
            Ok(Done::Audited(audit)) => {
                if self.hint[slot]
                    .as_ref()
                    .is_some_and(|hint| hint.comparison.id() == audit.offer)
                {
                    let state = if audit.complete {
                        "audited"
                    } else {
                        "audit_progress"
                    };
                    self.audited[slot] = Some(audit);
                    json!({"state":state})
                } else {
                    json!({"state":"failed","error":"peer offer changed during audit"})
                }
            }
            Ok(Done::Selected(registration)) => {
                self.shared[slot] = None;
                self.verified[slot] = None;
                self.hint[slot] = None;
                self.audited[slot] = None;
                json!({"state":"selected","model":registration.id()})
            }
            Err(error) => {
                json!({"state":"failed","error":error.chars().take(300).collect::<String>()})
            }
        };
        self.result[slot] = value;
        Ok(())
    }

    pub(super) async fn shutdown(&mut self) {
        if let Some(work) = self.work.take() {
            if work.cancellable {
                work.task.abort();
            }
            let _ = work.task.await;
        }
    }
}

fn select(
    profile: Profile,
    frontier: Option<&mut Frontier>,
    client: crate::jobs::Client,
    computation: Arc<crate::resources::Computation>,
    expected: String,
    candidate: Option<Arc<Bundle>>,
) -> Result<tokio::task::JoinHandle<Result<Done, String>>, crate::Error> {
    Ok(match profile {
        Profile::Solver => tokio::spawn(async move {
            Ok(Done::Selected(
                client.select_model(expected, candidate).await?,
            ))
        }),
        Profile::Finder => {
            let _work = computation.try_enter().ok_or("computation paused")?;
            let selected = frontier
                .ok_or("finder model owner unavailable")?
                .select_model(&expected, candidate.as_deref())?;
            tokio::spawn(async { Ok(Done::Selected(selected)) })
        }
    })
}

enum Snapshot {
    Solver,
    Finder(Bundle),
}

impl Snapshot {
    async fn get(self, client: &crate::jobs::Client) -> Result<Arc<Bundle>, String> {
        match self {
            Self::Solver => client.model_snapshot().await.map(Arc::new),
            Self::Finder(bundle) => Ok(Arc::new(bundle)),
        }
    }
}

fn prepare_snapshot(profile: Profile, frontier: Option<&Frontier>) -> Result<Snapshot, String> {
    Ok(match profile {
        Profile::Solver => Snapshot::Solver,
        Profile::Finder => Snapshot::Finder(
            frontier
                .ok_or("finder model owner unavailable")?
                .model_snapshot()?,
        ),
    })
}

fn parse_peer(own: PeerId, peer: &str) -> Result<PeerId, String> {
    let id = peer.parse::<PeerId>().map_err(|e| e.to_string())?;
    if id == own || id.to_string() != peer {
        return Err("comparison requires another canonical peer identity".into());
    }
    Ok(id)
}

fn new_challenge(
    signing: &libp2p::identity::Keypair,
    peer: PeerId,
    local: Registration,
    remote: Registration,
) -> Result<Challenge, String> {
    let mut nonce = [0; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut nonce))
        .map_err(|e| e.to_string())?;
    Challenge::new(nonce, signing, peer, local, remote)
}

pub(super) struct Outbound {
    pub(super) peer: PeerId,
    pub(super) body: Body,
    pub(super) reply: oneshot::Sender<Result<Packet, String>>,
}

async fn send(
    outbox: &mpsc::Sender<Outbound>,
    peer: PeerId,
    packet: Packet,
) -> Result<Packet, String> {
    let retry_read = matches!(packet, Packet::Inspect { .. } | Packet::Chunk { .. });
    let limits = crate::resources::limits();
    tokio::time::timeout(limits.request_timeout * 2, async {
        loop {
            let (reply, receiver) = oneshot::channel();
            outbox
                .send(Outbound {
                    peer,
                    body: Body::Model {
                        packet: packet.clone(),
                    },
                    reply,
                })
                .await
                .map_err(|_| "model transport unavailable")?;
            match receiver.await.map_err(|_| "model request cancelled")? {
                Err(reason)
                    if retry_read && matches!(reason.as_str(), OWNER_BUSY | "peer rate limit") =>
                {
                    tokio::time::sleep(limits.request_rate_window).await;
                }
                result => return result,
            }
        }
    })
    .await
    .map_err(|_| "model peer request timed out")?
}

async fn inspect(
    outbox: &mpsc::Sender<Outbound>,
    peer: PeerId,
    profile: Profile,
) -> Result<(Registration, usize), String> {
    let Packet::Manifest {
        registration,
        chunk_limit,
    } = send(outbox, peer, Packet::Inspect { profile }).await?
    else {
        return Err("model manifest response differs".into());
    };
    registration.validate()?;
    if registration.model.profile() != profile || chunk_limit < 1024 {
        return Err("model profile or peer chunk capacity differs".into());
    }
    let width = chunk_limit.min(protocol::chunk_limit());
    if width < 1024 {
        return Err("local model wire chunk capacity is too small".into());
    }
    Ok((registration, width))
}

async fn download(
    outbox: &mpsc::Sender<Outbound>,
    peer: PeerId,
    registration: Registration,
    width: usize,
) -> Result<Bundle, String> {
    // Apply the same peer request windows throughout the bounded transfer.
    // The local proof transport can retain priority and stall model work.
    let deadline = crate::resources::limits().root_timeout * 4;
    tokio::time::timeout(deadline, download_parts(outbox, peer, registration, width))
        .await
        .map_err(|_| "model transfer deadline expired")?
}

async fn download_parts(
    outbox: &mpsc::Sender<Outbound>,
    peer: PeerId,
    registration: Registration,
    width: usize,
) -> Result<Bundle, String> {
    let memory = Bundle::reserve(&registration)?;
    let id = registration.id();
    let mut parts = Vec::new();
    for blob in registration.model.blobs() {
        let mut bytes = Vec::with_capacity(blob.bytes);
        while bytes.len() < blob.bytes {
            let offset = bytes.len();
            let length = (blob.bytes - offset).min(width);
            let Packet::ChunkData {
                model,
                blob: received,
                offset: position,
                data,
            } = send(
                outbox,
                peer,
                Packet::Chunk {
                    model: id.clone(),
                    blob: blob.clone(),
                    offset,
                    length,
                },
            )
            .await?
            else {
                return Err("model chunk response differs".into());
            };
            if model != id || received != *blob || position != offset {
                return Err("model chunk binding differs".into());
            }
            bytes.extend(protocol::decode(&data, length)?);
            // Pace our stream even if this connection can answer faster.
            let limits = crate::resources::limits();
            let pace = limits.request_rate_window / limits.request_burst as u32;
            tokio::time::sleep(pace).await;
        }
        parts.push(bytes);
    }
    Bundle::new(registration, parts, memory)
}
