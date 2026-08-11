//! Bounded acquisition of one unselected addressed proof closure.

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use libp2p::request_response::OutboundRequestId;
use naome::proof_exchange::ProofRequest;
use naome_chain::{ProofBlock, ProofBlockApplyError};
use naome_ledger::{AcceptedProofRecord, AddressedProofCandidate, PROOF_BATCH_MAX_CANDIDATES};
use naome_proof::{ProofCertificate, ProofCertificateError, ProofId, ProofNormalForm, ProofStep};
use naome_storage::{ProofChainJournal, ProofChainJournalError};

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
        selected: &ProofChainJournal,
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
    pub(super) fn belongs_to_network(&self, network: &StaticProofNetwork) -> bool {
        Arc::ptr_eq(
            &self.cancellation.control().network_budget,
            &network.pending_budget,
        )
    }

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
        selected: &ProofChainJournal,
        event: OutboundProofEvent,
    ) -> Result<DependencyAcquisitionProgress, DependencyAcquisitionError> {
        if !self.belongs_to_network(network)
            || !Arc::ptr_eq(&event.control.network_budget, &network.pending_budget)
        {
            return Err(DependencyAcquisitionError::NetworkInstanceMismatch);
        }
        if !self.accepts_event(&event) {
            return Err(DependencyAcquisitionError::UnexpectedEvent);
        }
        let OutboundProofEvent {
            peer_id, outcome, ..
        } = event;

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
/// candidates. A caller-supplied exact-parent block is the only way to release
/// its contents to durable selected state.
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

    /// Atomically checks, address-binds, selects, and persists this closure as
    /// one caller-supplied block.
    ///
    /// Candidate buffers are correlated into the block's exact identity order
    /// without changing the block. Missing, extra, duplicate, or substituted
    /// candidates remain authoritative block-application errors. The selected
    /// state may also have changed since acquisition, so parentage,
    /// canonicality, mathematics, identities, dependencies, and roots are all
    /// revalidated before journal I/O.
    pub fn apply_block<'journal>(
        self,
        selected: &'journal mut ProofChainJournal,
        block: &ProofBlock,
    ) -> Result<&'journal AcceptedProofRecord, ProofChainJournalError> {
        let expected_parent = selected.head_block_id()?;
        let actual_parent = block.parent_block_id();
        if actual_parent != expected_parent {
            return Err(ProofChainJournalError::BlockAdmission {
                source: ProofBlockApplyError::ParentBlockIdMismatch {
                    expected: expected_parent,
                    actual: actual_parent,
                },
            });
        }

        let Self {
            candidates,
            requested_root: _,
        } = self;

        let mut candidates = candidates;
        let proof_ids = block.transition().proof_ids();
        candidates.sort_unstable_by_key(|candidate| {
            proof_ids
                .iter()
                .position(|proof_id| *proof_id == candidate.expected_proof_id)
                .unwrap_or(proof_ids.len())
        });

        let mut addressed = Vec::with_capacity(candidates.len());
        for candidate in &mut candidates {
            addressed.push(AddressedProofCandidate::new(
                candidate.expected_proof_id,
                std::mem::take(&mut candidate.canonical_proof_bytes),
            ));
        }
        let result = selected.apply_block(block, addressed);
        drop(candidates);
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
    SelectedState { source: ProofChainJournalError },
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
mod tests;
