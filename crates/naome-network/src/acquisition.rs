//! Bounded acquisition of one unselected addressed proof closure.

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use libp2p::request_response::OutboundRequestId;
use naome::proof_exchange::ProofRequest;
use naome_ledger::{AcceptedProofRecord, AddressedProofCandidate, PROOF_BATCH_MAX_CANDIDATES};
use naome_proof::{ProofCertificate, ProofCertificateError, ProofId, ProofNormalForm, ProofStep};
use naome_storage::{JournalError, ProofDagJournal};

use super::{
    AcquisitionControl, DEPENDENCY_ACQUISITION_TIMEOUT, MAX_DEPENDENCY_ACQUISITION_REQUESTS,
    OutboundProofEvent, OutboundProofFailure, OutboundProofOutcome, PeerId, PendingPermit,
    RequestStartError, StaticProofNetwork,
};

/// One caller-driven acquisition of a bounded proof-reference closure.
///
/// The acquisition validates only certificate structure and canonical normal
/// form. It may retry one address across the bounded configured-peer set after
/// `Unavailable` or an ordinary transport failure, while retaining one
/// request, deadline, and acquisition-wide request budget. Its quarantined
/// bytes remain unselected and untrusted until a completed
/// [`UnselectedProofClosure`] is atomically applied to selected state.
#[must_use]
pub struct ProofDependencyAcquisition {
    cancellation: CancellationGuard,
    peer_id: PeerId,
    requested_root: ProofId,
    pending_request: ProofRequest,
    pending_request_id: OutboundRequestId,
    attempted_peers: u8,
    attempts_issued: u8,
    discovered: Vec<ProofId>,
    candidates: Vec<QuarantinedCandidate>,
}

struct CancellationGuard {
    control: Option<Arc<AcquisitionControl>>,
}

impl CancellationGuard {
    fn new(control: Arc<AcquisitionControl>) -> Self {
        Self {
            control: Some(control),
        }
    }

    fn control(&self) -> &Arc<AcquisitionControl> {
        self.control
            .as_ref()
            .expect("an active acquisition retains cancellation control")
    }

    fn disarm(&mut self) {
        self.control = None;
    }
}

impl Drop for CancellationGuard {
    fn drop(&mut self) {
        if let Some(control) = &self.control {
            control.cancel();
        }
    }
}

enum RequestSelectionError {
    NoEligiblePeer,
    AttemptLimit,
    RequestStart(RequestStartError),
}

fn map_request_selection_error(
    proof_id: ProofId,
    source: RequestSelectionError,
) -> DependencyAcquisitionError {
    match source {
        RequestSelectionError::NoEligiblePeer => {
            DependencyAcquisitionError::NoEligiblePeer { proof_id }
        }
        RequestSelectionError::AttemptLimit => DependencyAcquisitionError::RequestAttemptLimit {
            pending_proof_id: proof_id,
            maximum: MAX_DEPENDENCY_ACQUISITION_REQUESTS,
        },
        RequestSelectionError::RequestStart(source) => {
            DependencyAcquisitionError::RequestStart { proof_id, source }
        }
    }
}

fn start_next_acquisition_attempt(
    network: &mut StaticProofNetwork,
    preferred_peer_id: PeerId,
    request: ProofRequest,
    control: &Arc<AcquisitionControl>,
    attempted_peers: &mut u8,
    attempts_issued: &mut u8,
) -> Result<(PeerId, OutboundRequestId), RequestSelectionError> {
    let (preferred_index, peer_count) = {
        let sessions = &network.swarm.behaviour().sessions;
        let preferred_index =
            sessions
                .peer_index(&preferred_peer_id)
                .ok_or(RequestSelectionError::RequestStart(
                    RequestStartError::UnknownPeer(preferred_peer_id),
                ))?;
        (preferred_index, sessions.peer_count())
    };

    if usize::from(*attempts_issued) >= MAX_DEPENDENCY_ACQUISITION_REQUESTS {
        return Err(RequestSelectionError::AttemptLimit);
    }

    for position in 0..peer_count {
        let index = if position == 0 {
            preferred_index
        } else {
            let ordered = position - 1;
            if ordered < preferred_index {
                ordered
            } else {
                ordered + 1
            }
        };
        let bit = 1_u8
            .checked_shl(u32::try_from(index).expect("the peer index fits u32"))
            .expect("the static peer count fits one attempted-peer mask");
        if *attempted_peers & bit != 0 {
            continue;
        }
        *attempted_peers |= bit;

        let peer_id = network
            .swarm
            .behaviour()
            .sessions
            .peer_id_at(index)
            .expect("the configured peer index remains stable");
        match network.request_acquisition_proof(peer_id, request, control) {
            Ok(request_id) => {
                *attempts_issued = attempts_issued
                    .checked_add(1)
                    .expect("the acquisition request bound fits u8");
                return Ok((peer_id, request_id));
            }
            Err(RequestStartError::AlreadyPending(_) | RequestStartError::PeerDisconnected(_)) => {}
            Err(source) => return Err(RequestSelectionError::RequestStart(source)),
        }
    }

    Err(RequestSelectionError::NoEligiblePeer)
}

impl StaticProofNetwork {
    /// Starts acquiring the root-reachable proof references absent from
    /// `selected`.
    ///
    /// `peer_id` is tried first. A retryable remote terminal may advance to an
    /// unattempted configured peer, but exactly one request remains active for
    /// this acquisition. The caller must continue driving
    /// [`Self::next_event`](StaticProofNetwork::next_event) and pass the
    /// correlated outbound event to
    /// [`ProofDependencyAcquisition::on_event`].
    pub fn start_dependency_acquisition(
        &mut self,
        selected: &ProofDagJournal,
        peer_id: PeerId,
        requested_root: ProofId,
    ) -> Result<ProofDependencyAcquisition, DependencyAcquisitionError> {
        if selected
            .proof(requested_root)
            .map_err(|source| DependencyAcquisitionError::SelectedState { source })?
            .is_some()
        {
            return Err(DependencyAcquisitionError::RootAlreadySelected {
                proof_id: requested_root,
            });
        }

        let deadline = tokio::time::Instant::now()
            .checked_add(DEPENDENCY_ACQUISITION_TIMEOUT)
            .expect("the fixed acquisition timeout fits Tokio Instant");
        let control = Arc::new(AcquisitionControl::new(
            Arc::clone(&self.pending_budget),
            deadline,
        ));
        let pending_request = ProofRequest::new(requested_root);
        let mut attempted_peers = 0;
        let mut attempts_issued = 0;
        let (peer_id, pending_request_id) = start_next_acquisition_attempt(
            self,
            peer_id,
            pending_request,
            &control,
            &mut attempted_peers,
            &mut attempts_issued,
        )
        .map_err(|source| map_request_selection_error(requested_root, source))?;

        let mut discovered = Vec::with_capacity(PROOF_BATCH_MAX_CANDIDATES);
        discovered.push(requested_root);
        Ok(ProofDependencyAcquisition {
            cancellation: CancellationGuard::new(control),
            peer_id,
            requested_root,
            pending_request,
            pending_request_id,
            attempted_peers,
            attempts_issued,
            discovered,
            candidates: Vec::with_capacity(PROOF_BATCH_MAX_CANDIDATES),
        })
    }
}

impl ProofDependencyAcquisition {
    /// Returns the peer serving the currently pending request.
    pub const fn pending_peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the exact request whose terminal event this acquisition awaits.
    pub const fn pending_request(&self) -> ProofRequest {
        self.pending_request
    }

    /// Cancels this acquisition while the transport drains its current
    /// request.
    ///
    /// Already quarantined candidates are released immediately. The current
    /// request continues to occupy its peer slot and one global permit until
    /// libp2p emits its terminal response or failure.
    pub fn cancel(self) {}

    /// Returns whether `event` is the exact terminal outcome awaited by this
    /// acquisition generation.
    ///
    /// Callers driving more than one logical workflow can use this predicate
    /// to route a late event without consuming an unrelated acquisition.
    pub fn accepts_event(&self, event: &OutboundProofEvent) -> bool {
        Arc::ptr_eq(self.cancellation.control(), &event.control)
            && event.request_id == self.pending_request_id
            && event.peer_id == self.peer_id
            && event.request == self.pending_request
    }

    /// Consumes the expected terminal event and either starts the next dependency
    /// request or returns the complete unselected closure.
    ///
    /// `network` must be the same instance that started this acquisition;
    /// instance identity is checked before payload interpretation.
    ///
    /// `selected` is consulted only for proof-reference membership. It is not
    /// mutated. Callers should pass the same logical journal throughout one
    /// acquisition, though its append-only state may grow between calls. Final
    /// atomic admission repeats every authoritative validation against the
    /// then-current selected state.
    pub fn on_event(
        mut self,
        network: &mut StaticProofNetwork,
        selected: &ProofDagJournal,
        event: OutboundProofEvent,
    ) -> Result<DependencyAcquisitionProgress, DependencyAcquisitionError> {
        if !Arc::ptr_eq(
            &self.cancellation.control().network_budget,
            &network.pending_budget,
        ) || !Arc::ptr_eq(&event.control.network_budget, &network.pending_budget)
        {
            return Err(DependencyAcquisitionError::NetworkInstanceMismatch);
        }
        let OutboundProofEvent {
            request_id,
            peer_id,
            request,
            outcome,
            ..
        } = event;

        if !Arc::ptr_eq(self.cancellation.control(), &event.control)
            || request_id != self.pending_request_id
            || peer_id != self.peer_id
            || request != self.pending_request
        {
            return Err(DependencyAcquisitionError::UnexpectedEvent);
        }

        let proof_id = self.pending_request.proof_id();
        let outcome = match outcome {
            OutboundProofOutcome::Failure(source) => match source.as_ref() {
                OutboundProofFailure::PeerMismatch { .. } => {
                    return Err(DependencyAcquisitionError::RequestFailed {
                        peer_id,
                        proof_id,
                        source,
                    });
                }
                OutboundProofFailure::Transport(_) => OutboundProofOutcome::Failure(source),
            },
            outcome => outcome,
        };
        if matches!(outcome, OutboundProofOutcome::DeadlineExceeded) || self.deadline_expired() {
            return Err(self.deadline_error());
        }
        let (response, permit) = match outcome {
            OutboundProofOutcome::Response { response, _permit } => (response, _permit),
            OutboundProofOutcome::Failure(source) => {
                let error = DependencyAcquisitionError::RequestFailed {
                    peer_id,
                    proof_id,
                    source,
                };
                return self.retry_current_request(network, error);
            }
            OutboundProofOutcome::DeadlineExceeded => unreachable!("handled above"),
        };
        if response.is_unavailable() {
            drop(response);
            drop(permit);
            let error = DependencyAcquisitionError::Unavailable { peer_id, proof_id };
            return self.retry_current_request(network, error);
        }

        let normal_form = decode_canonical_candidate(proof_id, response.into_wire_bytes())?;
        let mut direct_dependencies = Vec::new();

        for step in normal_form.certificate().steps() {
            let ProofStep::ProofReference {
                proof_id: dependency,
            } = step
            else {
                continue;
            };
            let dependency = *dependency;

            if self.discovered.contains(&dependency) {
                direct_dependencies.push(dependency);
                continue;
            }
            if selected
                .proof(dependency)
                .map_err(|source| DependencyAcquisitionError::SelectedState { source })?
                .is_some()
            {
                continue;
            }

            let actual = self.discovered.len() + 1;
            if actual > PROOF_BATCH_MAX_CANDIDATES {
                return Err(DependencyAcquisitionError::TooManyCandidates {
                    actual,
                    maximum: PROOF_BATCH_MAX_CANDIDATES,
                });
            }
            self.discovered.push(dependency);
            direct_dependencies.push(dependency);
        }

        let canonical_proof_bytes = normal_form.into_canonical_bytes().into_vec();
        self.candidates.push(QuarantinedCandidate {
            expected_proof_id: proof_id,
            canonical_proof_bytes,
            direct_dependencies,
            _permit: permit,
        });

        if self.deadline_expired() {
            return Err(self.deadline_error());
        }

        if let Some(next_proof_id) = self.discovered.get(self.candidates.len()).copied() {
            let next_request = ProofRequest::new(next_proof_id);
            self.attempted_peers = 0;
            let (next_peer_id, next_request_id) = start_next_acquisition_attempt(
                network,
                self.peer_id,
                next_request,
                self.cancellation.control(),
                &mut self.attempted_peers,
                &mut self.attempts_issued,
            )
            .map_err(|source| map_request_selection_error(next_proof_id, source))?;
            self.peer_id = next_peer_id;
            self.pending_request = next_request;
            self.pending_request_id = next_request_id;
            return Ok(DependencyAcquisitionProgress::AwaitingResponse(self));
        }

        let order = dependency_order(&self.candidates, self.requested_root)?;
        if self.deadline_expired() {
            return Err(self.deadline_error());
        }
        debug_assert_eq!(order.len(), self.candidates.len());
        self.cancellation.disarm();
        let mut candidates = self.candidates.into_iter().map(Some).collect::<Vec<_>>();
        let candidates = order
            .into_iter()
            .map(|index| {
                candidates[index]
                    .take()
                    .expect("each quarantined candidate occurs once in dependency order")
            })
            .collect();

        Ok(DependencyAcquisitionProgress::Complete(
            UnselectedProofClosure {
                requested_root: self.requested_root,
                candidates,
            },
        ))
    }

    fn deadline_expired(&self) -> bool {
        tokio::time::Instant::now() >= self.cancellation.control().deadline
    }

    fn deadline_error(&self) -> DependencyAcquisitionError {
        DependencyAcquisitionError::DeadlineExceeded {
            peer_id: self.peer_id,
            pending_proof_id: self.pending_request.proof_id(),
        }
    }

    fn retry_current_request(
        mut self,
        network: &mut StaticProofNetwork,
        terminal_error: DependencyAcquisitionError,
    ) -> Result<DependencyAcquisitionProgress, DependencyAcquisitionError> {
        if self.deadline_expired() {
            return Err(self.deadline_error());
        }
        let request = self.pending_request;
        let (peer_id, request_id) = match start_next_acquisition_attempt(
            network,
            self.peer_id,
            request,
            self.cancellation.control(),
            &mut self.attempted_peers,
            &mut self.attempts_issued,
        ) {
            Ok(started) => started,
            Err(RequestSelectionError::NoEligiblePeer) => return Err(terminal_error),
            Err(source) => {
                return Err(map_request_selection_error(request.proof_id(), source));
            }
        };
        self.peer_id = peer_id;
        self.pending_request_id = request_id;
        Ok(DependencyAcquisitionProgress::AwaitingResponse(self))
    }
}

impl fmt::Debug for ProofDependencyAcquisition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProofDependencyAcquisition")
            .field("peer_id", &self.peer_id)
            .field("requested_root", &self.requested_root)
            .field("pending_request", &self.pending_request)
            .field("attempts_issued", &self.attempts_issued)
            .field("candidate_count", &self.candidates.len())
            .finish_non_exhaustive()
    }
}

/// The result of advancing one dependency acquisition event.
#[derive(Debug)]
#[must_use]
pub enum DependencyAcquisitionProgress {
    /// One new proof request was started and awaits its correlated response.
    AwaitingResponse(ProofDependencyAcquisition),
    /// Every root-reachable absent address was acquired exactly once.
    Complete(UnselectedProofClosure),
}

/// A structurally canonical, bounded addressed closure that is not selected.
///
/// This type deliberately exposes neither proof buffers nor addressed
/// candidates. Consuming atomic admission is the only way to release its
/// contents to selected state.
#[must_use]
pub struct UnselectedProofClosure {
    requested_root: ProofId,
    candidates: Vec<QuarantinedCandidate>,
}

impl UnselectedProofClosure {
    /// Returns the immutable root address requested for this closure.
    pub const fn requested_root(&self) -> ProofId {
        self.requested_root
    }

    /// Returns the number of quarantined proof candidates.
    pub fn candidate_count(&self) -> usize {
        self.candidates.len()
    }

    /// Atomically checks, address-binds, selects, and persists this closure.
    ///
    /// The selected state may have changed since acquisition. The existing
    /// rooted batch transaction revalidates canonicality, mathematics,
    /// identities, dependencies, duplicates, and root reachability before any
    /// mutation or journal write.
    pub fn apply_to_selected_state(
        self,
        selected: &mut ProofDagJournal,
    ) -> Result<&AcceptedProofRecord, JournalError> {
        let Self {
            requested_root,
            candidates,
        } = self;
        let (addressed, permits): (Vec<_>, Vec<_>) = candidates
            .into_iter()
            .map(QuarantinedCandidate::into_addressed_and_permit)
            .unzip();
        let result = selected.apply_rooted_canonical_proof_batch(requested_root, addressed);
        drop(permits);
        result
    }
}

impl fmt::Debug for UnselectedProofClosure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnselectedProofClosure")
            .field("requested_root", &self.requested_root)
            .field("candidate_count", &self.candidates.len())
            .finish_non_exhaustive()
    }
}

struct QuarantinedCandidate {
    expected_proof_id: ProofId,
    canonical_proof_bytes: Vec<u8>,
    direct_dependencies: Vec<ProofId>,
    _permit: PendingPermit,
}

impl QuarantinedCandidate {
    fn into_addressed_and_permit(self) -> (AddressedProofCandidate, PendingPermit) {
        (
            AddressedProofCandidate::new(self.expected_proof_id, self.canonical_proof_bytes),
            self._permit,
        )
    }
}

fn decode_canonical_candidate(
    proof_id: ProofId,
    bytes: Vec<u8>,
) -> Result<ProofNormalForm, DependencyAcquisitionError> {
    let certificate = ProofCertificate::from_canonical_bytes(&bytes)
        .map_err(|source| DependencyAcquisitionError::Decode { proof_id, source })?;
    certificate
        .into_unchecked_normal_form()
        .with_matching_canonical_bytes(bytes.into_boxed_slice())
        .ok_or(DependencyAcquisitionError::NonCanonical { proof_id })
}

fn dependency_order(
    candidates: &[QuarantinedCandidate],
    requested_root: ProofId,
) -> Result<Vec<usize>, DependencyAcquisitionError> {
    let root = candidates
        .iter()
        .position(|candidate| candidate.expected_proof_id == requested_root)
        .expect("the requested root is the first acquired candidate");
    let mut marks = vec![VisitMark::Unvisited; candidates.len()];
    let mut order = Vec::with_capacity(candidates.len());
    visit_candidate(root, candidates, &mut marks, &mut order)?;
    Ok(order)
}

fn visit_candidate(
    index: usize,
    candidates: &[QuarantinedCandidate],
    marks: &mut [VisitMark],
    order: &mut Vec<usize>,
) -> Result<(), DependencyAcquisitionError> {
    marks[index] = VisitMark::Visiting;
    for dependency_index in 0..candidates[index].direct_dependencies.len() {
        let dependency = candidates[index].direct_dependencies[dependency_index];
        let referenced = candidates
            .iter()
            .position(|candidate| candidate.expected_proof_id == dependency)
            .expect("every unselected direct dependency was acquired");
        match marks[referenced] {
            VisitMark::Unvisited => visit_candidate(referenced, candidates, marks, order)?,
            VisitMark::Visiting => {
                return Err(DependencyAcquisitionError::DependencyCycle {
                    from: candidates[index].expected_proof_id,
                    dependency,
                });
            }
            VisitMark::Visited => {}
        }
    }
    marks[index] = VisitMark::Visited;
    order.push(index);
    Ok(())
}

#[derive(Clone, Copy)]
enum VisitMark {
    Unvisited,
    Visiting,
    Visited,
}

/// A fail-closed bounded dependency-acquisition error.
#[derive(Debug)]
#[non_exhaustive]
pub enum DependencyAcquisitionError {
    /// The selected journal could not answer a read-only membership query.
    SelectedState { source: JournalError },
    /// The requested root was already present when acquisition started.
    RootAlreadySelected { proof_id: ProofId },
    /// The next single-flight request could not be started.
    RequestStart {
        proof_id: ProofId,
        source: RequestStartError,
    },
    /// No configured peer was currently connected and free for this address.
    NoEligiblePeer { proof_id: ProofId },
    /// The whole-acquisition request budget was exhausted before completion.
    RequestAttemptLimit {
        pending_proof_id: ProofId,
        maximum: usize,
    },
    /// The event or driver belongs to another transport instance.
    NetworkInstanceMismatch,
    /// The supplied event did not belong to this acquisition generation.
    UnexpectedEvent,
    /// The request failed before the deadline, or its terminal peer mismatched
    /// the immutable request correlation.
    RequestFailed {
        peer_id: PeerId,
        proof_id: ProofId,
        source: Box<OutboundProofFailure>,
    },
    /// The immutable acquisition deadline was reached.
    DeadlineExceeded {
        peer_id: PeerId,
        pending_proof_id: ProofId,
    },
    /// The authenticated peer reported no payload for a required address.
    Unavailable { peer_id: PeerId, proof_id: ProofId },
    /// A response was not one structurally valid complete certificate.
    Decode {
        proof_id: ProofId,
        source: ProofCertificateError,
    },
    /// A response certificate was not already its root-proof normal form.
    NonCanonical { proof_id: ProofId },
    /// Root-reachable absent addresses exceeded the atomic batch bound.
    TooManyCandidates { actual: usize, maximum: usize },
    /// Address-level proof references formed a cycle.
    DependencyCycle { from: ProofId, dependency: ProofId },
}

impl fmt::Display for DependencyAcquisitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelectedState { source } => {
                write!(formatter, "cannot inspect selected proof state: {source}")
            }
            Self::RootAlreadySelected { proof_id } => {
                write!(
                    formatter,
                    "requested proof {proof_id:?} is already selected"
                )
            }
            Self::RequestStart { proof_id, source } => {
                write!(formatter, "cannot request proof {proof_id:?}: {source}")
            }
            Self::NoEligiblePeer { proof_id } => {
                write!(
                    formatter,
                    "no configured peer can currently serve proof {proof_id:?}"
                )
            }
            Self::RequestAttemptLimit {
                pending_proof_id,
                maximum,
            } => write!(
                formatter,
                "proof acquisition cannot issue another request for {pending_proof_id:?} after {maximum} requests"
            ),
            Self::NetworkInstanceMismatch => {
                formatter.write_str("acquisition was routed through another network instance")
            }
            Self::UnexpectedEvent => {
                formatter.write_str("outbound event does not belong to this acquisition")
            }
            Self::RequestFailed {
                peer_id,
                proof_id,
                source,
            } => {
                write!(
                    formatter,
                    "peer {peer_id} failed proof request {proof_id:?}: {source}"
                )
            }
            Self::DeadlineExceeded {
                peer_id,
                pending_proof_id,
            } => {
                write!(
                    formatter,
                    "proof acquisition from {peer_id} exceeded {DEPENDENCY_ACQUISITION_TIMEOUT:?} while awaiting {pending_proof_id:?}"
                )
            }
            Self::Unavailable { peer_id, proof_id } => {
                write!(formatter, "peer {peer_id} has no proof at {proof_id:?}")
            }
            Self::Decode { proof_id, source } => {
                write!(formatter, "proof {proof_id:?} cannot be decoded: {source}")
            }
            Self::NonCanonical { proof_id } => {
                write!(formatter, "proof {proof_id:?} is not canonical normal form")
            }
            Self::TooManyCandidates { actual, maximum } => write!(
                formatter,
                "proof closure has {actual} candidates, exceeding maximum {maximum}"
            ),
            Self::DependencyCycle { from, dependency } => write!(
                formatter,
                "proof-reference cycle reaches {dependency:?} from {from:?}"
            ),
        }
    }
}

impl Error for DependencyAcquisitionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SelectedState { source } => Some(source),
            Self::RequestStart { source, .. } => Some(source),
            Self::RequestFailed { source, .. } => Some(source.as_ref()),
            Self::Decode { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use libp2p::request_response;
    use libp2p::swarm::ConnectionId;
    use naome::proof_exchange::ProofResponse;
    use naome_foundation::{FreeVariable, ZfcAxiom};
    use naome_ledger::ProofBatchError;

    use super::*;
    use crate::{CancellationDrainOutcome, NetworkEvent, PendingBudget, StaticPeer};

    static TEMP_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new(label: &str) -> Self {
            loop {
                let sequence = TEMP_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
                let path = env::temp_dir().join(format!(
                    "naome-network-acquisition-{label}-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self { path },
                    Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(source) => panic!("temporary test directory failed: {source}"),
                }
            }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn journal_bytes(&self) -> Vec<u8> {
            fs::read(self.path.join("proof-dag.journal")).unwrap()
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).unwrap();
        }
    }

    fn proof_id(byte: u8) -> ProofId {
        ProofId::from_bytes([byte; 32])
    }

    fn pairing_bytes() -> Vec<u8> {
        vec![0x00, 0x00, 0x00, 0x01, 0x10, 0x01]
    }

    fn canonical_bytes(steps: Vec<ProofStep>) -> Vec<u8> {
        ProofCertificate::new(steps)
            .unwrap()
            .into_unchecked_normal_form()
            .into_canonical_bytes()
            .into_vec()
    }

    fn reference_closure_bytes(dependencies: &[ProofId]) -> Vec<u8> {
        assert!(!dependencies.is_empty());
        let mut steps = dependencies
            .iter()
            .copied()
            .map(|proof_id| ProofStep::ProofReference { proof_id })
            .collect::<Vec<_>>();
        let mut root = 0_u32;
        for next in 1..dependencies.len() {
            steps.push(ProofStep::ModusPonens {
                premise: root,
                implication: u32::try_from(next).unwrap(),
            });
            root = u32::try_from(steps.len() - 1).unwrap();
        }
        canonical_bytes(steps)
    }

    fn referenced_generalization_bytes(parent: ProofId) -> Vec<u8> {
        canonical_bytes(vec![
            ProofStep::ProofReference { proof_id: parent },
            ProofStep::Generalization {
                premise: 0,
                variable: FreeVariable::new(7),
            },
        ])
    }

    fn valid_parent_and_root() -> (Vec<u8>, ProofId, Vec<u8>, ProofId) {
        let directory = TestDirectory::new("source");
        let mut journal = ProofDagJournal::create(directory.path()).unwrap();
        let parent_bytes = pairing_bytes();
        let parent_id = journal
            .apply_canonical_proof_bytes(parent_bytes.clone())
            .unwrap()
            .proof_id();
        let root_bytes = referenced_generalization_bytes(parent_id);
        let root_id = journal
            .apply_canonical_proof_bytes(root_bytes.clone())
            .unwrap()
            .proof_id();
        (parent_bytes, parent_id, root_bytes, root_id)
    }

    fn test_network() -> (StaticProofNetwork, PeerId) {
        let remote = crate::Keypair::generate_ed25519();
        let remote_peer_id = remote.public().to_peer_id();
        (test_network_for_peer(remote_peer_id), remote_peer_id)
    }

    fn test_network_for_peer(remote_peer_id: PeerId) -> StaticProofNetwork {
        test_network_for_peers(&[remote_peer_id])
    }

    fn test_network_for_peers(remote_peer_ids: &[PeerId]) -> StaticProofNetwork {
        let local = crate::Keypair::generate_ed25519();
        assert!(!remote_peer_ids.contains(&local.public().to_peer_id()));
        let peers = remote_peer_ids
            .iter()
            .copied()
            .enumerate()
            .map(|(index, peer_id)| {
                let address = format!("/ip4/127.0.0.1/tcp/{}", 9 + index).parse().unwrap();
                StaticPeer::new(peer_id, address)
            })
            .collect::<Vec<_>>();
        let mut network = StaticProofNetwork::new(local, peers).unwrap();
        for &peer_id in remote_peer_ids {
            network
                .swarm
                .behaviour_mut()
                .sessions
                .mark_connected_for_test(peer_id);
        }
        network
    }

    fn response_for(
        network: &mut StaticProofNetwork,
        acquisition: &ProofDependencyAcquisition,
        bytes: Vec<u8>,
    ) -> OutboundProofEvent {
        let request_id = acquisition.pending_request_id;
        let pending = network
            .pending
            .remove(&request_id)
            .expect("the acquisition request is pending");
        OutboundProofEvent {
            request_id,
            peer_id: pending.peer_id,
            request: pending.request,
            control: Arc::clone(&pending.control),
            outcome: OutboundProofOutcome::Response {
                response: ProofResponse::from_wire_bytes(bytes).unwrap(),
                _permit: pending._permit,
            },
        }
    }

    fn transport_response(
        network: &mut StaticProofNetwork,
        request_id: OutboundRequestId,
        peer_id: PeerId,
        bytes: Vec<u8>,
    ) -> NetworkEvent {
        network
            .handle_exchange_event(request_response::Event::Message {
                peer: peer_id,
                connection_id: ConnectionId::new_unchecked(700),
                message: request_response::Message::Response {
                    request_id,
                    response: ProofResponse::from_wire_bytes(bytes).unwrap(),
                },
            })
            .expect("the retained request produces one terminal event")
    }

    fn transport_failure(
        network: &mut StaticProofNetwork,
        request_id: OutboundRequestId,
        peer_id: PeerId,
        error: request_response::OutboundFailure,
    ) -> NetworkEvent {
        network
            .handle_exchange_event(request_response::Event::OutboundFailure {
                peer: peer_id,
                connection_id: ConnectionId::new_unchecked(701),
                request_id,
                error,
            })
            .expect("the retained request produces one terminal event")
    }

    fn start(
        network: &mut StaticProofNetwork,
        selected: &ProofDagJournal,
        peer_id: PeerId,
        requested_root: ProofId,
    ) -> ProofDependencyAcquisition {
        network
            .start_dependency_acquisition(selected, peer_id, requested_root)
            .unwrap()
    }

    fn candidate(id: u8, dependencies: &[u8]) -> QuarantinedCandidate {
        let budget = Arc::new(PendingBudget::default());
        let permit = PendingBudget::try_acquire(&budget).unwrap();
        QuarantinedCandidate {
            expected_proof_id: proof_id(id),
            canonical_proof_bytes: vec![id],
            direct_dependencies: dependencies.iter().map(|byte| proof_id(*byte)).collect(),
            _permit: permit,
        }
    }

    #[test]
    fn shared_dependency_order_is_unique_dependency_first_and_root_last() {
        let candidates = vec![candidate(3, &[1, 2]), candidate(1, &[2]), candidate(2, &[])];

        let order = dependency_order(&candidates, proof_id(3)).unwrap();
        let ordered_ids = order
            .into_iter()
            .map(|index| candidates[index].expected_proof_id)
            .collect::<Vec<_>>();

        assert_eq!(ordered_ids, [proof_id(2), proof_id(1), proof_id(3)]);
    }

    #[test]
    fn address_cycle_reports_the_closing_edge() {
        let candidates = vec![candidate(2, &[1]), candidate(1, &[2])];

        assert!(matches!(
            dependency_order(&candidates, proof_id(2)),
            Err(DependencyAcquisitionError::DependencyCycle { from, dependency })
                if from == proof_id(1) && dependency == proof_id(2)
        ));
    }

    #[test]
    fn closure_debug_does_not_expose_candidate_bytes() {
        let closure = UnselectedProofClosure {
            requested_root: proof_id(9),
            candidates: vec![candidate(9, &[])],
        };

        let debug = format!("{closure:?}");
        assert!(debug.contains("candidate_count: 1"));
        assert!(!debug.contains("canonical_proof_bytes"));
    }

    #[test]
    fn addressed_conversion_keeps_the_payload_permit_separate() {
        let budget = Arc::new(PendingBudget::default());
        let permit = PendingBudget::try_acquire(&budget).unwrap();
        let candidate = QuarantinedCandidate {
            expected_proof_id: proof_id(0x33),
            canonical_proof_bytes: pairing_bytes(),
            direct_dependencies: Vec::new(),
            _permit: permit,
        };

        let (addressed, permit) = candidate.into_addressed_and_permit();
        drop(addressed);
        assert_eq!(budget.active.load(Ordering::Relaxed), 1);
        drop(permit);
        assert_eq!(budget.active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn selected_dependency_is_a_cut_and_promotion_adds_only_the_root() {
        let (parent_bytes, parent_id, root_bytes, root_id) = valid_parent_and_root();
        let directory = TestDirectory::new("selected-cut");
        let mut selected = ProofDagJournal::create(directory.path()).unwrap();
        selected.apply_canonical_proof_bytes(parent_bytes).unwrap();
        let before = directory.journal_bytes();
        let before_root = selected.proof_set_root().unwrap();
        let (mut network, peer_id) = test_network();
        let acquisition = start(&mut network, &selected, peer_id, root_id);
        let response = response_for(&mut network, &acquisition, root_bytes);

        let DependencyAcquisitionProgress::Complete(closure) = acquisition
            .on_event(&mut network, &selected, response)
            .unwrap()
        else {
            panic!("selected dependency unexpectedly caused another request");
        };
        assert_eq!(closure.candidate_count(), 1);
        assert_eq!(directory.journal_bytes(), before);
        assert_eq!(selected.proof_set_root().unwrap(), before_root);
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);

        assert_eq!(
            closure
                .apply_to_selected_state(&mut selected)
                .unwrap()
                .proof_id(),
            root_id
        );
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
        assert_eq!(selected.len().unwrap(), 2);
        assert!(selected.proof(parent_id).unwrap().is_some());
    }

    #[test]
    fn selected_root_and_unknown_peer_fail_before_a_request_is_retained() {
        let directory = TestDirectory::new("start-preflight");
        let mut selected = ProofDagJournal::create(directory.path()).unwrap();
        let selected_root = selected
            .apply_canonical_proof_bytes(pairing_bytes())
            .unwrap()
            .proof_id();
        let (mut network, peer_id) = test_network();

        assert!(matches!(
            network.start_dependency_acquisition(&selected, peer_id, selected_root),
            Err(DependencyAcquisitionError::RootAlreadySelected { proof_id })
                if proof_id == selected_root
        ));
        assert!(network.pending.is_empty());
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);

        let unknown = crate::Keypair::generate_ed25519().public().to_peer_id();
        let requested = proof_id(0x40);
        assert!(matches!(
            network.start_dependency_acquisition(&selected, unknown, requested),
            Err(DependencyAcquisitionError::RequestStart { proof_id, source: RequestStartError::UnknownPeer(actual) })
                if proof_id == requested && actual == unknown
        ));
        assert!(network.pending.is_empty());
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);

        let disconnected_peer = crate::Keypair::generate_ed25519().public().to_peer_id();
        let disconnected_address = "/ip4/127.0.0.1/tcp/1".parse().unwrap();
        let mut disconnected = StaticProofNetwork::new(
            crate::Keypair::generate_ed25519(),
            [StaticPeer::new(disconnected_peer, disconnected_address)],
        )
        .unwrap();
        assert!(matches!(
            disconnected.start_dependency_acquisition(
                &selected,
                disconnected_peer,
                requested,
            ),
            Err(DependencyAcquisitionError::NoEligiblePeer { proof_id })
                if proof_id == requested
        ));
        assert!(disconnected.pending.is_empty());
        assert_eq!(
            disconnected.pending_budget.active.load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn unavailable_and_malformed_responses_drop_the_complete_quarantine() {
        let directory = TestDirectory::new("terminal-response-errors");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let before = directory.journal_bytes();

        for (bytes, decode) in [(Vec::new(), false), (vec![0xff], true)] {
            let (mut network, peer_id) = test_network();
            let requested = proof_id(0x41);
            let acquisition = start(&mut network, &selected, peer_id, requested);
            let response = response_for(&mut network, &acquisition, bytes);
            let error = acquisition
                .on_event(&mut network, &selected, response)
                .unwrap_err();
            assert!(
                matches!(error, DependencyAcquisitionError::Decode { proof_id, .. } if decode && proof_id == requested)
                    || matches!(error, DependencyAcquisitionError::Unavailable { peer_id: actual_peer, proof_id } if !decode && actual_peer == peer_id && proof_id == requested)
            );
            assert!(network.pending.is_empty());
            assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
            assert_eq!(directory.journal_bytes(), before);
        }
    }

    #[test]
    fn unavailable_retries_the_same_request_after_releasing_its_permit() {
        let directory = TestDirectory::new("unavailable-fallback");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let preferred = crate::Keypair::generate_ed25519().public().to_peer_id();
        let fallback = crate::Keypair::generate_ed25519().public().to_peer_id();
        let mut network = test_network_for_peers(&[fallback, preferred]);
        let requested = proof_id(0xa0);
        let acquisition = start(&mut network, &selected, preferred, requested);
        let control = Arc::clone(acquisition.cancellation.control());
        let other_permits = (0..crate::MAX_PENDING_REQUESTS - 1)
            .map(|_| PendingBudget::try_acquire(&network.pending_budget).unwrap())
            .collect::<Vec<_>>();
        let response = response_for(&mut network, &acquisition, Vec::new());
        assert_eq!(
            network.pending_budget.active.load(Ordering::Relaxed),
            crate::MAX_PENDING_REQUESTS
        );

        let DependencyAcquisitionProgress::AwaitingResponse(acquisition) = acquisition
            .on_event(&mut network, &selected, response)
            .unwrap()
        else {
            panic!("unavailable preferred peer did not start fallback");
        };
        assert_eq!(acquisition.pending_peer_id(), fallback);
        assert_eq!(acquisition.pending_request(), ProofRequest::new(requested));
        assert_eq!(acquisition.attempts_issued, 2);
        assert!(Arc::ptr_eq(acquisition.cancellation.control(), &control));
        assert_eq!(
            network.pending_budget.active.load(Ordering::Relaxed),
            crate::MAX_PENDING_REQUESTS
        );
        assert_eq!(network.pending.len(), 1);
        drop(other_permits);
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);

        let response = response_for(&mut network, &acquisition, Vec::new());
        assert!(matches!(
            acquisition.on_event(&mut network, &selected, response),
            Err(DependencyAcquisitionError::Unavailable { peer_id, proof_id })
                if peer_id == fallback && proof_id == requested
        ));
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn fallback_visits_preferred_then_raw_order_without_repeating_a_peer() {
        let directory = TestDirectory::new("fallback-order");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let mut peers = [
            crate::Keypair::generate_ed25519().public().to_peer_id(),
            crate::Keypair::generate_ed25519().public().to_peer_id(),
            crate::Keypair::generate_ed25519().public().to_peer_id(),
        ];
        peers.sort_unstable_by_key(|peer_id| peer_id.to_bytes());
        let [first, second, preferred] = peers;
        let mut network = test_network_for_peers(&[second, preferred, first]);
        let requested = proof_id(0xa6);
        let acquisition = start(&mut network, &selected, preferred, requested);
        assert_eq!(acquisition.pending_peer_id(), preferred);

        let unavailable = response_for(&mut network, &acquisition, Vec::new());
        let DependencyAcquisitionProgress::AwaitingResponse(acquisition) = acquisition
            .on_event(&mut network, &selected, unavailable)
            .unwrap()
        else {
            panic!("first fallback did not start");
        };
        assert_eq!(acquisition.pending_peer_id(), first);

        let unavailable = response_for(&mut network, &acquisition, Vec::new());
        let DependencyAcquisitionProgress::AwaitingResponse(acquisition) = acquisition
            .on_event(&mut network, &selected, unavailable)
            .unwrap()
        else {
            panic!("second fallback did not start");
        };
        assert_eq!(acquisition.pending_peer_id(), second);
        assert_eq!(acquisition.attempts_issued, 3);

        let unavailable = response_for(&mut network, &acquisition, Vec::new());
        assert!(matches!(
            acquisition.on_event(&mut network, &selected, unavailable),
            Err(DependencyAcquisitionError::Unavailable { peer_id, proof_id })
                if peer_id == second && proof_id == requested
        ));
        assert!(network.pending.is_empty());
    }

    #[test]
    fn disconnected_and_busy_peers_are_skipped_without_consuming_attempts() {
        let directory = TestDirectory::new("fallback-skips");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let mut peers = [
            crate::Keypair::generate_ed25519().public().to_peer_id(),
            crate::Keypair::generate_ed25519().public().to_peer_id(),
            crate::Keypair::generate_ed25519().public().to_peer_id(),
        ];
        peers.sort_unstable_by_key(|peer_id| peer_id.to_bytes());
        let [disconnected, busy, available] = peers;
        let mut network = test_network_for_peers(&[available, disconnected, busy]);
        network
            .swarm
            .behaviour_mut()
            .sessions
            .mark_disconnected_for_test(disconnected);
        network
            .request_proof(busy, ProofRequest::new(proof_id(0xb0)))
            .unwrap();

        let acquisition = start(&mut network, &selected, disconnected, proof_id(0xb1));
        assert_eq!(acquisition.pending_peer_id(), available);
        assert_eq!(acquisition.attempts_issued, 1);
        assert_eq!(network.pending.len(), 2);
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn transport_failure_falls_back_without_reusing_the_failed_peer() {
        let directory = TestDirectory::new("transport-fallback");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let preferred = crate::Keypair::generate_ed25519().public().to_peer_id();
        let fallback = crate::Keypair::generate_ed25519().public().to_peer_id();
        let mut network = test_network_for_peers(&[preferred, fallback]);
        let requested = proof_id(0xa1);
        let acquisition = start(&mut network, &selected, preferred, requested);
        let event = transport_failure(
            &mut network,
            acquisition.pending_request_id,
            preferred,
            request_response::OutboundFailure::Timeout,
        );
        let NetworkEvent::OutboundProof(event) = event else {
            panic!("transport failure was not surfaced");
        };

        let DependencyAcquisitionProgress::AwaitingResponse(acquisition) = acquisition
            .on_event(&mut network, &selected, event)
            .unwrap()
        else {
            panic!("transport failure did not start fallback");
        };
        assert_eq!(acquisition.pending_peer_id(), fallback);
        assert_eq!(acquisition.pending_request(), ProofRequest::new(requested));
        assert_eq!(acquisition.attempts_issued, 2);
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn fallback_provider_is_preferred_for_the_next_dependency() {
        let (parent_bytes, parent_id, root_bytes, root_id) = valid_parent_and_root();
        let directory = TestDirectory::new("fallback-stickiness");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let preferred = crate::Keypair::generate_ed25519().public().to_peer_id();
        let fallback = crate::Keypair::generate_ed25519().public().to_peer_id();
        let mut network = test_network_for_peers(&[preferred, fallback]);
        let acquisition = start(&mut network, &selected, preferred, root_id);
        let unavailable = response_for(&mut network, &acquisition, Vec::new());
        let DependencyAcquisitionProgress::AwaitingResponse(acquisition) = acquisition
            .on_event(&mut network, &selected, unavailable)
            .unwrap()
        else {
            panic!("root fallback did not start");
        };
        assert_eq!(acquisition.pending_peer_id(), fallback);

        let root = response_for(&mut network, &acquisition, root_bytes);
        let DependencyAcquisitionProgress::AwaitingResponse(acquisition) =
            acquisition.on_event(&mut network, &selected, root).unwrap()
        else {
            panic!("root did not discover its parent");
        };
        assert_eq!(acquisition.pending_peer_id(), fallback);
        assert_eq!(acquisition.pending_request(), ProofRequest::new(parent_id));
        assert_eq!(acquisition.attempts_issued, 3);
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 2);

        let parent = response_for(&mut network, &acquisition, parent_bytes);
        let DependencyAcquisitionProgress::Complete(closure) = acquisition
            .on_event(&mut network, &selected, parent)
            .unwrap()
        else {
            panic!("two-candidate closure did not complete");
        };
        assert_eq!(closure.candidate_count(), 2);
    }

    #[test]
    fn malformed_and_noncanonical_candidates_do_not_fall_back() {
        let directory = TestDirectory::new("structural-errors-do-not-fallback");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let preferred = crate::Keypair::generate_ed25519().public().to_peer_id();
        let fallback = crate::Keypair::generate_ed25519().public().to_peer_id();
        let noncanonical = ProofCertificate::new(vec![
            ProofStep::ProofReference {
                proof_id: proof_id(0x77),
            },
            ProofStep::ZfcAxiom(ZfcAxiom::Pairing),
        ])
        .unwrap()
        .to_canonical_bytes();

        for bytes in [vec![0xff], noncanonical] {
            let mut network = test_network_for_peers(&[fallback, preferred]);
            let requested = proof_id(0xa2);
            let acquisition = start(&mut network, &selected, preferred, requested);
            let response = response_for(&mut network, &acquisition, bytes);
            let error = acquisition
                .on_event(&mut network, &selected, response)
                .unwrap_err();
            assert!(matches!(
                error,
                DependencyAcquisitionError::Decode { .. }
                    | DependencyAcquisitionError::NonCanonical { .. }
            ));
            assert!(network.pending.is_empty());
            assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn request_attempt_limit_never_resets_for_a_new_dependency() {
        let directory = TestDirectory::new("request-attempt-limit");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let (mut network, peer_id) = test_network();
        let requested = proof_id(0xa3);
        let first_dependency = proof_id(0xa4);
        let second_dependency = proof_id(0xa5);
        let mut acquisition = start(&mut network, &selected, peer_id, requested);
        acquisition.attempts_issued =
            u8::try_from(MAX_DEPENDENCY_ACQUISITION_REQUESTS - 1).unwrap();
        let root = response_for(
            &mut network,
            &acquisition,
            reference_closure_bytes(&[first_dependency]),
        );
        let DependencyAcquisitionProgress::AwaitingResponse(acquisition) =
            acquisition.on_event(&mut network, &selected, root).unwrap()
        else {
            panic!("the final permitted request was not issued");
        };
        assert_eq!(
            usize::from(acquisition.attempts_issued),
            MAX_DEPENDENCY_ACQUISITION_REQUESTS
        );

        let dependency = response_for(
            &mut network,
            &acquisition,
            reference_closure_bytes(&[second_dependency]),
        );
        assert!(matches!(
            acquisition.on_event(&mut network, &selected, dependency),
            Err(DependencyAcquisitionError::RequestAttemptLimit {
                pending_proof_id,
                maximum,
            }) if pending_proof_id == second_dependency
                && maximum == MAX_DEPENDENCY_ACQUISITION_REQUESTS
        ));
        assert!(network.pending.is_empty());
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn seven_fallbacks_and_eight_candidates_complete_at_exact_request_limit() {
        let directory = TestDirectory::new("exact-request-limit-completion");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let peer_ids = (0..crate::MAX_STATIC_PEERS)
            .map(|_| crate::Keypair::generate_ed25519().public().to_peer_id())
            .collect::<Vec<_>>();
        let mut network = test_network_for_peers(&peer_ids);
        let requested = proof_id(0xc0);
        let dependencies = (1..PROOF_BATCH_MAX_CANDIDATES)
            .map(|index| proof_id(u8::try_from(0xc0 + index).unwrap()))
            .collect::<Vec<_>>();
        let mut acquisition = start(&mut network, &selected, peer_ids[0], requested);

        for _ in 0..crate::MAX_STATIC_PEERS - 1 {
            let unavailable = response_for(&mut network, &acquisition, Vec::new());
            let DependencyAcquisitionProgress::AwaitingResponse(next) = acquisition
                .on_event(&mut network, &selected, unavailable)
                .unwrap()
            else {
                panic!("bounded root fallback terminated before the eighth peer");
            };
            acquisition = next;
        }

        let root = response_for(
            &mut network,
            &acquisition,
            reference_closure_bytes(&[dependencies[0]]),
        );
        let DependencyAcquisitionProgress::AwaitingResponse(next) =
            acquisition.on_event(&mut network, &selected, root).unwrap()
        else {
            panic!("root did not request its first dependency");
        };
        acquisition = next;

        for window in dependencies.windows(2) {
            let response = response_for(
                &mut network,
                &acquisition,
                reference_closure_bytes(&[window[1]]),
            );
            let DependencyAcquisitionProgress::AwaitingResponse(next) = acquisition
                .on_event(&mut network, &selected, response)
                .unwrap()
            else {
                panic!("dependency chain completed before its leaf");
            };
            acquisition = next;
        }

        assert_eq!(
            usize::from(acquisition.attempts_issued),
            MAX_DEPENDENCY_ACQUISITION_REQUESTS
        );
        let leaf = response_for(&mut network, &acquisition, pairing_bytes());
        let DependencyAcquisitionProgress::Complete(closure) =
            acquisition.on_event(&mut network, &selected, leaf).unwrap()
        else {
            panic!("exact-limit closure did not complete");
        };
        assert_eq!(closure.candidate_count(), PROOF_BATCH_MAX_CANDIDATES);
        assert_eq!(
            network.pending_budget.active.load(Ordering::Relaxed),
            PROOF_BATCH_MAX_CANDIDATES
        );
        drop(closure);
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn fifteenth_terminal_request_cannot_start_a_sixteenth_attempt() {
        let directory = TestDirectory::new("terminal-request-attempt-limit");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let preferred = crate::Keypair::generate_ed25519().public().to_peer_id();
        let fallback = crate::Keypair::generate_ed25519().public().to_peer_id();
        let mut network = test_network_for_peers(&[preferred, fallback]);
        let requested = proof_id(0xa7);
        let mut acquisition = start(&mut network, &selected, preferred, requested);
        acquisition.attempts_issued = u8::try_from(MAX_DEPENDENCY_ACQUISITION_REQUESTS).unwrap();
        let unavailable = response_for(&mut network, &acquisition, Vec::new());

        assert!(matches!(
            acquisition.on_event(&mut network, &selected, unavailable),
            Err(DependencyAcquisitionError::RequestAttemptLimit {
                pending_proof_id,
                maximum,
            }) if pending_proof_id == requested
                && maximum == MAX_DEPENDENCY_ACQUISITION_REQUESTS
        ));
        assert!(network.pending.is_empty());
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn noncanonical_candidate_cannot_trigger_an_unreachable_reference_request() {
        let directory = TestDirectory::new("noncanonical");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let (mut network, peer_id) = test_network();
        let requested = proof_id(0x42);
        let unreachable = proof_id(0x99);
        let bytes = ProofCertificate::new(vec![
            ProofStep::ProofReference {
                proof_id: unreachable,
            },
            ProofStep::ZfcAxiom(ZfcAxiom::Pairing),
        ])
        .unwrap()
        .to_canonical_bytes();
        let acquisition = start(&mut network, &selected, peer_id, requested);
        let response = response_for(&mut network, &acquisition, bytes);

        assert!(matches!(
            acquisition.on_event(&mut network, &selected, response),
            Err(DependencyAcquisitionError::NonCanonical { proof_id }) if proof_id == requested
        ));
        assert!(network.pending.is_empty());
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
        assert!(selected.proof(unreachable).unwrap().is_none());
    }

    #[test]
    fn ninth_absent_candidate_is_rejected_before_another_request() {
        let directory = TestDirectory::new("candidate-bound");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let (mut network, peer_id) = test_network();
        let requested = proof_id(0x50);
        let dependencies = (0..PROOF_BATCH_MAX_CANDIDATES)
            .map(|index| proof_id(u8::try_from(index + 1).unwrap()))
            .collect::<Vec<_>>();
        let acquisition = start(&mut network, &selected, peer_id, requested);
        let response = response_for(
            &mut network,
            &acquisition,
            reference_closure_bytes(&dependencies),
        );

        assert!(matches!(
            acquisition.on_event(&mut network, &selected, response),
            Err(DependencyAcquisitionError::TooManyCandidates { actual, maximum })
                if actual == PROOF_BATCH_MAX_CANDIDATES + 1
                    && maximum == PROOF_BATCH_MAX_CANDIDATES
        ));
        assert!(network.pending.is_empty());
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn exact_maximum_closure_holds_all_permits_until_drop() {
        let directory = TestDirectory::new("maximum-closure");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let (mut network, peer_id) = test_network();
        let requested = proof_id(0x51);
        let dependencies = (0..PROOF_BATCH_MAX_CANDIDATES - 1)
            .map(|index| proof_id(u8::try_from(index + 1).unwrap()))
            .collect::<Vec<_>>();
        let acquisition = start(&mut network, &selected, peer_id, requested);
        let response = response_for(
            &mut network,
            &acquisition,
            reference_closure_bytes(&dependencies),
        );
        let DependencyAcquisitionProgress::AwaitingResponse(mut acquisition) = acquisition
            .on_event(&mut network, &selected, response)
            .unwrap()
        else {
            panic!("maximum closure did not request its dependencies");
        };

        let closure = loop {
            let response = response_for(&mut network, &acquisition, pairing_bytes());
            match acquisition
                .on_event(&mut network, &selected, response)
                .unwrap()
            {
                DependencyAcquisitionProgress::AwaitingResponse(next) => acquisition = next,
                DependencyAcquisitionProgress::Complete(closure) => break closure,
            }
        };
        assert_eq!(closure.candidate_count(), PROOF_BATCH_MAX_CANDIDATES);
        assert_eq!(
            network.pending_budget.active.load(Ordering::Relaxed),
            PROOF_BATCH_MAX_CANDIDATES
        );
        drop(closure);
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
        assert!(selected.is_empty().unwrap());
    }

    #[test]
    fn repeated_and_shared_references_are_requested_once() {
        let directory = TestDirectory::new("reference-dedup");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let (mut network, peer_id) = test_network();
        let requested = proof_id(0x52);
        let first = proof_id(0x01);
        let shared = proof_id(0x02);
        let acquisition = start(&mut network, &selected, peer_id, requested);
        let response = response_for(
            &mut network,
            &acquisition,
            reference_closure_bytes(&[first, first, shared]),
        );
        let DependencyAcquisitionProgress::AwaitingResponse(acquisition) = acquisition
            .on_event(&mut network, &selected, response)
            .unwrap()
        else {
            panic!("root did not request its first unique dependency");
        };
        assert_eq!(acquisition.pending_request().proof_id(), first);

        let response = response_for(
            &mut network,
            &acquisition,
            reference_closure_bytes(&[shared]),
        );
        let DependencyAcquisitionProgress::AwaitingResponse(acquisition) = acquisition
            .on_event(&mut network, &selected, response)
            .unwrap()
        else {
            panic!("shared dependency was not requested");
        };
        assert_eq!(acquisition.pending_request().proof_id(), shared);
        let response = response_for(&mut network, &acquisition, pairing_bytes());
        let DependencyAcquisitionProgress::Complete(closure) = acquisition
            .on_event(&mut network, &selected, response)
            .unwrap()
        else {
            panic!("deduplicated closure did not complete");
        };
        assert_eq!(closure.candidate_count(), 3);
        assert!(network.pending.is_empty());
        drop(closure);
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn later_unavailable_response_discards_the_earlier_quarantine() {
        let directory = TestDirectory::new("later-unavailable");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let before = directory.journal_bytes();
        let (mut network, peer_id) = test_network();
        let requested = proof_id(0x53);
        let dependency = proof_id(0x54);
        let acquisition = start(&mut network, &selected, peer_id, requested);
        let response = response_for(
            &mut network,
            &acquisition,
            reference_closure_bytes(&[dependency]),
        );
        let DependencyAcquisitionProgress::AwaitingResponse(acquisition) = acquisition
            .on_event(&mut network, &selected, response)
            .unwrap()
        else {
            panic!("dependency was not requested");
        };
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 2);
        let response = response_for(&mut network, &acquisition, Vec::new());
        assert!(matches!(
            acquisition.on_event(&mut network, &selected, response),
            Err(DependencyAcquisitionError::Unavailable { proof_id, .. })
                if proof_id == dependency
        ));
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
        assert!(network.pending.is_empty());
        assert!(selected.is_empty().unwrap());
        assert_eq!(directory.journal_bytes(), before);
    }

    #[test]
    fn acquired_self_and_two_node_cycles_terminate_without_selection() {
        let directory = TestDirectory::new("cycles");
        let selected = ProofDagJournal::create(directory.path()).unwrap();

        let (mut self_network, self_peer) = test_network();
        let self_id = proof_id(0x61);
        let self_acquisition = start(&mut self_network, &selected, self_peer, self_id);
        let self_response = response_for(
            &mut self_network,
            &self_acquisition,
            reference_closure_bytes(&[self_id]),
        );
        assert!(matches!(
            self_acquisition.on_event(&mut self_network, &selected, self_response),
            Err(DependencyAcquisitionError::DependencyCycle { from, dependency })
                if from == self_id && dependency == self_id
        ));
        assert_eq!(
            self_network.pending_budget.active.load(Ordering::Relaxed),
            0
        );

        let (mut network, peer_id) = test_network();
        let root = proof_id(0x62);
        let child = proof_id(0x63);
        let acquisition = start(&mut network, &selected, peer_id, root);
        let response = response_for(
            &mut network,
            &acquisition,
            reference_closure_bytes(&[child]),
        );
        let DependencyAcquisitionProgress::AwaitingResponse(acquisition) = acquisition
            .on_event(&mut network, &selected, response)
            .unwrap()
        else {
            panic!("two-node cycle did not request its second node");
        };
        assert_eq!(acquisition.pending_request().proof_id(), child);
        let response = response_for(&mut network, &acquisition, reference_closure_bytes(&[root]));
        assert!(matches!(
            acquisition.on_event(&mut network, &selected, response),
            Err(DependencyAcquisitionError::DependencyCycle { from, dependency })
                if from == child && dependency == root
        ));
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
        assert!(selected.is_empty().unwrap());
    }

    #[test]
    fn stale_same_address_response_does_not_consume_a_new_generation() {
        let directory = TestDirectory::new("late-response");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let (mut network, peer_id) = test_network();
        let requested = proof_id(0x71);
        let first = start(&mut network, &selected, peer_id, requested);
        let stale = response_for(&mut network, &first, pairing_bytes());
        drop(first);

        let current = start(&mut network, &selected, peer_id, requested);
        assert!(!current.accepts_event(&stale));
        assert_eq!(current.pending_request().proof_id(), requested);
        drop(stale);
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);

        let response = response_for(&mut network, &current, pairing_bytes());
        let DependencyAcquisitionProgress::Complete(closure) =
            current.on_event(&mut network, &selected, response).unwrap()
        else {
            panic!("leaf candidate unexpectedly requested a dependency");
        };
        drop(closure);
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn unexpected_generation_precedes_payload_interpretation() {
        let directory = TestDirectory::new("unexpected-generation");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let (mut network, peer_id) = test_network();
        let requested = proof_id(0x74);
        let previous = start(&mut network, &selected, peer_id, requested);
        let stale_unavailable = response_for(&mut network, &previous, Vec::new());
        drop(previous);

        let current = start(&mut network, &selected, peer_id, requested);
        let current_request_id = current.pending_request_id;
        assert!(!current.accepts_event(&stale_unavailable));
        assert!(matches!(
            current.on_event(&mut network, &selected, stale_unavailable),
            Err(DependencyAcquisitionError::UnexpectedEvent)
        ));
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
        drop(network.pending.remove(&current_request_id));
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
        assert!(selected.is_empty().unwrap());
    }

    #[test]
    fn follow_up_request_must_use_the_originating_network_instance() {
        let directory = TestDirectory::new("follow-up-network-instance");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let remote = crate::Keypair::generate_ed25519();
        let peer_id = remote.public().to_peer_id();
        let mut origin = test_network_for_peer(peer_id);
        let mut wrong_driver = test_network_for_peer(peer_id);
        let requested = proof_id(0x73);
        let acquisition = start(&mut origin, &selected, peer_id, requested);
        let response = response_for(&mut origin, &acquisition, pairing_bytes());
        assert!(acquisition.accepts_event(&response));

        assert!(matches!(
            acquisition.on_event(&mut wrong_driver, &selected, response),
            Err(DependencyAcquisitionError::NetworkInstanceMismatch)
        ));
        assert_eq!(origin.pending_budget.active.load(Ordering::Relaxed), 0);
        assert_eq!(
            wrong_driver.pending_budget.active.load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn response_must_come_from_the_originating_network_instance() {
        let directory = TestDirectory::new("response-network-instance");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let remote = crate::Keypair::generate_ed25519();
        let peer_id = remote.public().to_peer_id();
        let mut origin = test_network_for_peer(peer_id);
        let mut other = test_network_for_peer(peer_id);
        let requested = proof_id(0x75);
        let acquisition = start(&mut origin, &selected, peer_id, requested);
        let origin_request_id = acquisition.pending_request_id;
        let other_acquisition = start(&mut other, &selected, peer_id, requested);
        let mut other_response = response_for(&mut other, &other_acquisition, pairing_bytes());
        other_response.request_id = origin_request_id;

        assert!(!acquisition.accepts_event(&other_response));
        assert!(matches!(
            acquisition.on_event(&mut origin, &selected, other_response),
            Err(DependencyAcquisitionError::NetworkInstanceMismatch)
        ));
        assert_eq!(other.pending_budget.active.load(Ordering::Relaxed), 0);
        assert_eq!(origin.pending_budget.active.load(Ordering::Relaxed), 1);
        drop(origin.pending.remove(&origin_request_id));
        assert_eq!(origin.pending_budget.active.load(Ordering::Relaxed), 0);
        drop(other_acquisition);
    }

    #[test]
    fn wrong_address_promotion_is_atomic_and_releases_its_permit() {
        let directory = TestDirectory::new("wrong-address");
        let mut selected = ProofDagJournal::create(directory.path()).unwrap();
        let before = directory.journal_bytes();
        let before_root = selected.proof_set_root().unwrap();
        let (mut network, peer_id) = test_network();
        let requested = proof_id(0x72);
        let acquisition = start(&mut network, &selected, peer_id, requested);
        let response = response_for(&mut network, &acquisition, pairing_bytes());
        let DependencyAcquisitionProgress::Complete(closure) = acquisition
            .on_event(&mut network, &selected, response)
            .unwrap()
        else {
            panic!("leaf candidate unexpectedly requested a dependency");
        };
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);

        assert!(matches!(
            closure.apply_to_selected_state(&mut selected),
            Err(JournalError::BatchAdmission { source })
                if matches!(*source, ProofBatchError::Candidate { index: 0, .. })
        ));
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
        assert_eq!(selected.proof_set_root().unwrap(), before_root);
        assert!(selected.is_empty().unwrap());
        assert_eq!(directory.journal_bytes(), before);
    }

    #[test]
    fn selected_state_drift_is_revalidated_without_filtering_the_closure() {
        let (parent_bytes, parent_id, root_bytes, root_id) = valid_parent_and_root();
        let directory = TestDirectory::new("state-drift");
        let mut selected = ProofDagJournal::create(directory.path()).unwrap();
        let (mut network, peer_id) = test_network();
        let acquisition = start(&mut network, &selected, peer_id, root_id);
        let response = response_for(&mut network, &acquisition, root_bytes);
        let DependencyAcquisitionProgress::AwaitingResponse(acquisition) = acquisition
            .on_event(&mut network, &selected, response)
            .unwrap()
        else {
            panic!("root dependency was not requested");
        };
        let response = response_for(&mut network, &acquisition, parent_bytes.clone());
        let DependencyAcquisitionProgress::Complete(closure) = acquisition
            .on_event(&mut network, &selected, response)
            .unwrap()
        else {
            panic!("complete two-node closure did not finish");
        };
        assert_eq!(closure.candidate_count(), 2);
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 2);

        selected.apply_canonical_proof_bytes(parent_bytes).unwrap();
        let before = directory.journal_bytes();
        let before_root = selected.proof_set_root().unwrap();
        let before_len = selected.len().unwrap();
        assert!(matches!(
            closure.apply_to_selected_state(&mut selected),
            Err(JournalError::BatchAdmission { source })
                if matches!(*source, ProofBatchError::Candidate { index: 0, .. })
        ));
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
        assert_eq!(selected.len().unwrap(), before_len);
        assert_eq!(selected.proof_set_root().unwrap(), before_root);
        assert!(selected.proof(parent_id).unwrap().is_some());
        assert!(selected.proof(root_id).unwrap().is_none());
        assert_eq!(directory.journal_bytes(), before);
    }

    #[test]
    fn cancellation_releases_quarantine_but_retains_the_wire_permit_until_drain() {
        let (parent_bytes, _parent_id, root_bytes, root_id) = valid_parent_and_root();
        let directory = TestDirectory::new("cancel-retains-wire-permit");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let before = directory.journal_bytes();
        let (mut network, peer_id) = test_network();
        let acquisition = start(&mut network, &selected, peer_id, root_id);
        let event = response_for(&mut network, &acquisition, root_bytes);
        let DependencyAcquisitionProgress::AwaitingResponse(acquisition) = acquisition
            .on_event(&mut network, &selected, event)
            .unwrap()
        else {
            panic!("root dependency was not requested");
        };
        let request_id = acquisition.pending_request_id;
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 2);

        acquisition.cancel();
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
        assert!(network.pending.contains_key(&request_id));
        assert!(network.pending[&request_id].control.is_cancelled());
        assert!(matches!(
            network.request_proof(peer_id, ProofRequest::new(proof_id(0x91))),
            Err(RequestStartError::AlreadyPending(actual)) if actual == peer_id
        ));

        let event = transport_response(&mut network, request_id, peer_id, parent_bytes);
        assert!(matches!(
            event,
            NetworkEvent::CancellationDrained {
                peer_id: actual,
                outcome: CancellationDrainOutcome::ResponseDiscarded,
                ..
            } if actual == peer_id
        ));
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
        assert!(network.pending.is_empty());
        assert!(selected.is_empty().unwrap());
        assert_eq!(directory.journal_bytes(), before);
    }

    #[test]
    fn cancelled_transport_failure_settles_once_with_its_typed_cause() {
        let directory = TestDirectory::new("cancel-failure-drain");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let (mut network, peer_id) = test_network();
        let acquisition = start(&mut network, &selected, peer_id, proof_id(0x92));
        let request_id = acquisition.pending_request_id;
        acquisition.cancel();

        let event = transport_failure(
            &mut network,
            request_id,
            peer_id,
            request_response::OutboundFailure::Timeout,
        );
        assert!(matches!(
            event,
            NetworkEvent::CancellationDrained {
                outcome: CancellationDrainOutcome::Failure(source),
                ..
            } if matches!(
                source.as_ref(),
                OutboundProofFailure::Transport(request_response::OutboundFailure::Timeout)
            )
        ));
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
        assert!(
            network
                .handle_exchange_event(request_response::Event::OutboundFailure {
                    peer: peer_id,
                    connection_id: ConnectionId::new_unchecked(702),
                    request_id,
                    error: request_response::OutboundFailure::Timeout,
                })
                .is_none()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn session_disconnect_does_not_settle_a_cancelled_request() {
        let directory = TestDirectory::new("cancel-disconnect-order");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let (mut network, peer_id) = test_network();
        let acquisition = start(&mut network, &selected, peer_id, proof_id(0x9b));
        let request_id = acquisition.pending_request_id;
        acquisition.cancel();

        network
            .swarm
            .behaviour_mut()
            .sessions
            .mark_disconnected_for_test(peer_id);
        assert!(matches!(
            network.next_event().await,
            NetworkEvent::PeerSession(crate::PeerSessionEvent::Disconnected {
                peer_id: disconnected,
            }) if disconnected == peer_id
        ));
        assert!(network.pending.contains_key(&request_id));
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
        assert!(matches!(
            network.request_proof(peer_id, ProofRequest::new(proof_id(0x9c))),
            Err(RequestStartError::AlreadyPending(actual)) if actual == peer_id
        ));

        assert!(matches!(
            transport_failure(
                &mut network,
                request_id,
                peer_id,
                request_response::OutboundFailure::ConnectionClosed,
            ),
            NetworkEvent::CancellationDrained {
                outcome: CancellationDrainOutcome::Failure(source),
                ..
            } if matches!(
                source.as_ref(),
                OutboundProofFailure::Transport(
                    request_response::OutboundFailure::ConnectionClosed
                )
            )
        ));
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
        assert!(matches!(
            network.request_proof(peer_id, ProofRequest::new(proof_id(0x9d))),
            Err(RequestStartError::PeerDisconnected(actual)) if actual == peer_id
        ));
    }

    #[test]
    fn cancelled_requests_retain_the_complete_global_budget_until_exact_drain() {
        let directory = TestDirectory::new("cancel-global-budget");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let peer_ids = (0..crate::MAX_PENDING_REQUESTS)
            .map(|_| crate::Keypair::generate_ed25519().public().to_peer_id())
            .collect::<Vec<_>>();
        let mut network = test_network_for_peers(&peer_ids);
        let request_ids = peer_ids
            .iter()
            .copied()
            .enumerate()
            .map(|(index, peer_id)| {
                let acquisition = start(
                    &mut network,
                    &selected,
                    peer_id,
                    proof_id(u8::try_from(0xa0 + index).unwrap()),
                );
                let request_id = acquisition.pending_request_id;
                acquisition.cancel();
                request_id
            })
            .collect::<Vec<_>>();

        assert_eq!(
            network.pending_budget.active.load(Ordering::Relaxed),
            crate::MAX_PENDING_REQUESTS
        );
        assert!(PendingBudget::try_acquire(&network.pending_budget).is_none());

        for (index, (&peer_id, &request_id)) in peer_ids.iter().zip(&request_ids).enumerate() {
            assert!(matches!(
                transport_response(&mut network, request_id, peer_id, pairing_bytes()),
                NetworkEvent::CancellationDrained {
                    outcome: CancellationDrainOutcome::ResponseDiscarded,
                    ..
                }
            ));
            assert_eq!(
                network.pending_budget.active.load(Ordering::Relaxed),
                crate::MAX_PENDING_REQUESTS - index - 1
            );
        }
        assert!(network.pending.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn next_event_expires_once_at_the_absolute_deadline_and_drains_later() {
        let directory = TestDirectory::new("absolute-deadline-event");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let (mut network, peer_id) = test_network();
        let acquisition = start(&mut network, &selected, peer_id, proof_id(0x93));
        let request_id = acquisition.pending_request_id;

        tokio::time::advance(DEPENDENCY_ACQUISITION_TIMEOUT).await;
        let event = network.next_event().await;
        let NetworkEvent::OutboundProof(event) = event else {
            panic!("absolute deadline did not produce an outbound proof event");
        };
        assert!(event.is_deadline_exceeded());
        assert!(acquisition.accepts_event(&event));
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
        assert!(network.pending[&request_id].control.is_cancelled());
        assert!(
            network
                .take_due_acquisition_deadline(tokio::time::Instant::now())
                .is_none()
        );
        assert!(matches!(
            acquisition.on_event(&mut network, &selected, event),
            Err(DependencyAcquisitionError::DeadlineExceeded {
                pending_proof_id,
                ..
            }) if pending_proof_id == proof_id(0x93)
        ));

        let event = transport_response(&mut network, request_id, peer_id, pairing_bytes());
        assert!(matches!(
            event,
            NetworkEvent::CancellationDrained {
                outcome: CancellationDrainOutcome::ResponseDiscarded,
                ..
            }
        ));
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_equality_expires_but_completed_closures_do_not() {
        let (parent_bytes, parent_id, _root_bytes, _root_id) = valid_parent_and_root();
        let directory = TestDirectory::new("deadline-boundary");
        let mut selected = ProofDagJournal::create(directory.path()).unwrap();
        let (mut network, peer_id) = test_network();

        let acquisition = start(&mut network, &selected, peer_id, parent_id);
        tokio::time::advance(DEPENDENCY_ACQUISITION_TIMEOUT - Duration::from_nanos(1)).await;
        let event = response_for(&mut network, &acquisition, parent_bytes.clone());
        let DependencyAcquisitionProgress::Complete(closure) = acquisition
            .on_event(&mut network, &selected, event)
            .unwrap()
        else {
            panic!("leaf closure did not complete before its deadline");
        };
        tokio::time::advance(Duration::from_nanos(2)).await;
        assert_eq!(
            closure
                .apply_to_selected_state(&mut selected)
                .unwrap()
                .proof_id(),
            parent_id
        );

        let requested = proof_id(0x94);
        let acquisition = start(&mut network, &selected, peer_id, requested);
        tokio::time::advance(DEPENDENCY_ACQUISITION_TIMEOUT).await;
        let event = response_for(&mut network, &acquisition, pairing_bytes());
        assert!(matches!(
            acquisition.on_event(&mut network, &selected, event),
            Err(DependencyAcquisitionError::DeadlineExceeded {
                pending_proof_id,
                ..
            }) if pending_proof_id == requested
        ));
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_precedes_unavailable_malformed_and_ordinary_transport_failure() {
        let directory = TestDirectory::new("deadline-error-precedence");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let peer_id = crate::Keypair::generate_ed25519().public().to_peer_id();
        let fallback = crate::Keypair::generate_ed25519().public().to_peer_id();
        let mut network = test_network_for_peers(&[peer_id, fallback]);

        for (requested, bytes) in [(proof_id(0xb0), Vec::new()), (proof_id(0xb1), vec![0xff])] {
            let acquisition = start(&mut network, &selected, peer_id, requested);
            tokio::time::advance(DEPENDENCY_ACQUISITION_TIMEOUT).await;
            let event = response_for(&mut network, &acquisition, bytes);
            assert!(matches!(
                acquisition.on_event(&mut network, &selected, event),
                Err(DependencyAcquisitionError::DeadlineExceeded {
                    pending_proof_id,
                    ..
                }) if pending_proof_id == requested
            ));
        }

        let requested = proof_id(0xb2);
        let acquisition = start(&mut network, &selected, peer_id, requested);
        tokio::time::advance(DEPENDENCY_ACQUISITION_TIMEOUT).await;
        let event = transport_failure(
            &mut network,
            acquisition.pending_request_id,
            peer_id,
            request_response::OutboundFailure::Timeout,
        );
        assert!(matches!(
            acquisition.on_event(&mut network, &selected, match event {
                NetworkEvent::OutboundProof(event) => event,
                _ => panic!("deadline did not replace the ordinary transport failure"),
            }),
            Err(DependencyAcquisitionError::DeadlineExceeded {
                pending_proof_id,
                ..
            }) if pending_proof_id == requested
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn equal_deadlines_are_emitted_once_in_request_generation_order() {
        let directory = TestDirectory::new("equal-deadline-order");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let peer_ids = (0..2)
            .map(|_| crate::Keypair::generate_ed25519().public().to_peer_id())
            .collect::<Vec<_>>();
        let mut network = test_network_for_peers(&peer_ids);
        let first = start(&mut network, &selected, peer_ids[0], proof_id(0xb3));
        let second = start(&mut network, &selected, peer_ids[1], proof_id(0xb4));

        tokio::time::advance(DEPENDENCY_ACQUISITION_TIMEOUT).await;
        let NetworkEvent::OutboundProof(first_event) = network
            .take_due_acquisition_deadline(tokio::time::Instant::now())
            .expect("the first equal deadline is due")
        else {
            panic!("deadline did not produce an outbound proof event");
        };
        assert!(first.accepts_event(&first_event));
        assert!(!second.accepts_event(&first_event));

        let NetworkEvent::OutboundProof(second_event) = network
            .take_due_acquisition_deadline(tokio::time::Instant::now())
            .expect("the second equal deadline is due")
        else {
            panic!("deadline did not produce an outbound proof event");
        };
        assert!(second.accepts_event(&second_event));
        assert!(
            network
                .take_due_acquisition_deadline(tokio::time::Instant::now())
                .is_none()
        );
    }

    #[test]
    fn every_dependency_request_inherits_one_control_and_deadline() {
        let (_parent_bytes, _parent_id, root_bytes, root_id) = valid_parent_and_root();
        let directory = TestDirectory::new("one-absolute-deadline");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let (mut network, peer_id) = test_network();
        let acquisition = start(&mut network, &selected, peer_id, root_id);
        let first_control = Arc::clone(acquisition.cancellation.control());
        let deadline = first_control.deadline;
        let event = response_for(&mut network, &acquisition, root_bytes);

        let DependencyAcquisitionProgress::AwaitingResponse(acquisition) = acquisition
            .on_event(&mut network, &selected, event)
            .unwrap()
        else {
            panic!("root dependency was not requested");
        };
        assert!(Arc::ptr_eq(
            &first_control,
            acquisition.cancellation.control()
        ));
        assert_eq!(acquisition.cancellation.control().deadline, deadline);
        assert!(Arc::ptr_eq(
            &network.pending[&acquisition.pending_request_id].control,
            &first_control
        ));
    }

    #[test]
    fn pre_deadline_failure_and_cancelled_peer_mismatch_are_typed() {
        let directory = TestDirectory::new("failure-precedence");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let (mut network, peer_id) = test_network();
        let acquisition = start(&mut network, &selected, peer_id, proof_id(0x95));
        let request_id = acquisition.pending_request_id;
        let event = transport_failure(
            &mut network,
            request_id,
            peer_id,
            request_response::OutboundFailure::ConnectionClosed,
        );
        let NetworkEvent::OutboundProof(event) = event else {
            panic!("active failure was not surfaced");
        };
        assert!(matches!(
            acquisition.on_event(&mut network, &selected, event),
            Err(DependencyAcquisitionError::RequestFailed {
                source,
                ..
            }) if matches!(
                source.as_ref(),
                OutboundProofFailure::Transport(
                    request_response::OutboundFailure::ConnectionClosed
                )
            )
        ));

        let requested = proof_id(0x96);
        let acquisition = start(&mut network, &selected, peer_id, requested);
        let request_id = acquisition.pending_request_id;
        acquisition
            .cancellation
            .control()
            .cancelled
            .store(true, Ordering::Relaxed);
        let actual = crate::Keypair::generate_ed25519().public().to_peer_id();
        let event = transport_response(&mut network, request_id, actual, pairing_bytes());
        assert!(matches!(
            event,
            NetworkEvent::CancellationDrained {
                outcome: CancellationDrainOutcome::Failure(source),
                ..
            } if matches!(
                source.as_ref(),
                OutboundProofFailure::PeerMismatch {
                        expected,
                        actual: received,
                } if *expected == peer_id && *received == actual
            )
        ));
        drop(acquisition);
    }

    #[tokio::test(start_paused = true)]
    async fn a_processed_peer_mismatch_outranks_the_acquisition_deadline() {
        let directory = TestDirectory::new("peer-mismatch-deadline");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let peer_id = crate::Keypair::generate_ed25519().public().to_peer_id();
        let fallback = crate::Keypair::generate_ed25519().public().to_peer_id();
        let mut network = test_network_for_peers(&[peer_id, fallback]);
        let requested = proof_id(0x98);
        let acquisition = start(&mut network, &selected, peer_id, requested);
        let request_id = acquisition.pending_request_id;
        tokio::time::advance(DEPENDENCY_ACQUISITION_TIMEOUT).await;
        let actual = fallback;
        let event = transport_response(&mut network, request_id, actual, pairing_bytes());
        let NetworkEvent::OutboundProof(event) = event else {
            panic!("active peer mismatch was not surfaced");
        };
        assert!(matches!(
            acquisition.on_event(&mut network, &selected, event),
            Err(DependencyAcquisitionError::RequestFailed {
                source,
                ..
            }) if matches!(
                source.as_ref(),
                OutboundProofFailure::PeerMismatch {
                    expected,
                    actual: received,
                } if *expected == peer_id && *received == actual
            )
        ));
        assert!(network.pending.is_empty());
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_deadline_emitted_first_preserves_later_peer_mismatch_on_drain() {
        let directory = TestDirectory::new("deadline-before-peer-mismatch");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let (mut network, peer_id) = test_network();
        let acquisition = start(&mut network, &selected, peer_id, proof_id(0xb5));
        let request_id = acquisition.pending_request_id;
        tokio::time::advance(DEPENDENCY_ACQUISITION_TIMEOUT).await;
        let deadline = network
            .take_due_acquisition_deadline(tokio::time::Instant::now())
            .expect("the logical deadline is due");

        let actual = crate::Keypair::generate_ed25519().public().to_peer_id();
        assert!(matches!(
            transport_response(&mut network, request_id, actual, pairing_bytes()),
            NetworkEvent::CancellationDrained {
                outcome: CancellationDrainOutcome::Failure(source),
                ..
            } if matches!(
                source.as_ref(),
                OutboundProofFailure::PeerMismatch {
                    expected,
                    actual: received,
                } if *expected == peer_id && *received == actual
            )
        ));
        let NetworkEvent::OutboundProof(deadline) = deadline else {
            panic!("logical deadline did not produce an outbound proof event");
        };
        assert!(matches!(
            acquisition.on_event(&mut network, &selected, deadline),
            Err(DependencyAcquisitionError::DeadlineExceeded { .. })
        ));
    }

    #[test]
    fn dropping_an_acquisition_tombstones_its_current_generation() {
        let directory = TestDirectory::new("drop-acquisition");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let (mut network, peer_id) = test_network();
        let acquisition = start(&mut network, &selected, peer_id, proof_id(0x99));
        let request_id = acquisition.pending_request_id;
        drop(acquisition);

        assert!(network.pending[&request_id].control.is_cancelled());
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
        let event = transport_response(&mut network, request_id, peer_id, pairing_bytes());
        assert!(matches!(
            event,
            NetworkEvent::CancellationDrained {
                outcome: CancellationDrainOutcome::ResponseDiscarded,
                ..
            }
        ));
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn stale_failure_cannot_consume_a_new_same_address_generation() {
        let directory = TestDirectory::new("stale-failure-generation");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let (mut network, peer_id) = test_network();
        let requested = proof_id(0x9a);
        let old = start(&mut network, &selected, peer_id, requested);
        let event = transport_failure(
            &mut network,
            old.pending_request_id,
            peer_id,
            request_response::OutboundFailure::Timeout,
        );
        let NetworkEvent::OutboundProof(stale) = event else {
            panic!("active failure was not surfaced");
        };
        drop(old);

        let current = start(&mut network, &selected, peer_id, requested);
        let current_request_id = current.pending_request_id;
        assert!(!current.accepts_event(&stale));
        assert!(matches!(
            current.on_event(&mut network, &selected, stale),
            Err(DependencyAcquisitionError::UnexpectedEvent)
        ));
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
        drop(network.pending.remove(&current_request_id));
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn dropping_the_network_releases_every_tombstoned_permit() {
        let directory = TestDirectory::new("drop-network-tombstones");
        let selected = ProofDagJournal::create(directory.path()).unwrap();
        let (mut network, peer_id) = test_network();
        let budget = Arc::clone(&network.pending_budget);
        start(&mut network, &selected, peer_id, proof_id(0x97)).cancel();
        assert_eq!(budget.active.load(Ordering::Relaxed), 1);
        drop(network);
        assert_eq!(budget.active.load(Ordering::Relaxed), 0);
    }
}
