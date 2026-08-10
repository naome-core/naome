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
    PeerId, PendingBudget, PendingPermit, ReceivedProofResponse, RequestStartError,
    StaticProofNetwork,
};

/// One caller-driven acquisition of a bounded proof-reference closure.
///
/// The acquisition validates only certificate structure and canonical normal
/// form. Its quarantined bytes remain unselected and untrusted until a
/// completed [`UnselectedProofClosure`] is atomically applied to selected
/// state.
#[must_use]
pub struct ProofDependencyAcquisition {
    network_budget: Arc<PendingBudget>,
    peer_id: PeerId,
    requested_root: ProofId,
    pending_request: ProofRequest,
    pending_request_id: OutboundRequestId,
    discovered: Vec<ProofId>,
    candidates: Vec<QuarantinedCandidate>,
}

impl StaticProofNetwork {
    /// Starts acquiring the root-reachable proof references absent from
    /// `selected`.
    ///
    /// Exactly one request is active for this acquisition. The caller must
    /// continue driving [`Self::next_event`](StaticProofNetwork::next_event)
    /// and pass the correlated response to
    /// [`ProofDependencyAcquisition::on_response`].
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

        let pending_request = ProofRequest::new(requested_root);
        let pending_request_id =
            self.request_proof(peer_id, pending_request)
                .map_err(|source| DependencyAcquisitionError::RequestStart {
                    proof_id: requested_root,
                    source,
                })?;

        let mut discovered = Vec::with_capacity(PROOF_BATCH_MAX_CANDIDATES);
        discovered.push(requested_root);
        Ok(ProofDependencyAcquisition {
            network_budget: Arc::clone(&self.pending_budget),
            peer_id,
            requested_root,
            pending_request,
            pending_request_id,
            discovered,
            candidates: Vec::with_capacity(PROOF_BATCH_MAX_CANDIDATES),
        })
    }
}

impl ProofDependencyAcquisition {
    /// Returns the sole peer used by this acquisition.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the exact request whose response advances this acquisition.
    pub const fn pending_request(&self) -> ProofRequest {
        self.pending_request
    }

    /// Returns whether `received` is the exact response awaited by this
    /// acquisition generation.
    ///
    /// Callers driving more than one logical workflow can use this predicate
    /// to route a late response without consuming an unrelated acquisition.
    pub fn accepts_response(&self, received: &ReceivedProofResponse) -> bool {
        Arc::ptr_eq(&self.network_budget, &received._permit.budget)
            && received.request_id == self.pending_request_id
            && received.peer_id == self.peer_id
            && received.request == self.pending_request
    }

    /// Consumes the expected response and either starts the next dependency
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
    pub fn on_response(
        mut self,
        network: &mut StaticProofNetwork,
        selected: &ProofDagJournal,
        received: ReceivedProofResponse,
    ) -> Result<DependencyAcquisitionProgress, DependencyAcquisitionError> {
        if !Arc::ptr_eq(&self.network_budget, &network.pending_budget)
            || !Arc::ptr_eq(&self.network_budget, &received._permit.budget)
        {
            return Err(DependencyAcquisitionError::NetworkInstanceMismatch);
        }
        let ReceivedProofResponse {
            request_id,
            peer_id,
            request,
            response,
            _permit,
        } = received;

        if request_id != self.pending_request_id
            || peer_id != self.peer_id
            || request != self.pending_request
        {
            return Err(DependencyAcquisitionError::UnexpectedResponse);
        }

        let proof_id = self.pending_request.proof_id();
        if response.is_unavailable() {
            return Err(DependencyAcquisitionError::Unavailable { peer_id, proof_id });
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
            _permit,
        });

        if let Some(next_proof_id) = self.discovered.get(self.candidates.len()).copied() {
            let next_request = ProofRequest::new(next_proof_id);
            let next_request_id =
                network
                    .request_proof(self.peer_id, next_request)
                    .map_err(|source| DependencyAcquisitionError::RequestStart {
                        proof_id: next_proof_id,
                        source,
                    })?;
            self.pending_request = next_request;
            self.pending_request_id = next_request_id;
            return Ok(DependencyAcquisitionProgress::AwaitingResponse(self));
        }

        let order = dependency_order(&self.candidates, self.requested_root)?;
        debug_assert_eq!(order.len(), self.candidates.len());
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
}

impl fmt::Debug for ProofDependencyAcquisition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProofDependencyAcquisition")
            .field("peer_id", &self.peer_id)
            .field("requested_root", &self.requested_root)
            .field("pending_request", &self.pending_request)
            .field("candidate_count", &self.candidates.len())
            .finish_non_exhaustive()
    }
}

/// The result of advancing one dependency acquisition response.
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
    /// The response or driver belongs to another transport instance.
    NetworkInstanceMismatch,
    /// The supplied response did not belong to this acquisition generation.
    UnexpectedResponse,
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
            Self::NetworkInstanceMismatch => {
                formatter.write_str("acquisition was routed through another network instance")
            }
            Self::UnexpectedResponse => {
                formatter.write_str("response does not belong to this acquisition")
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

    use naome::proof_exchange::ProofResponse;
    use naome_foundation::{FreeVariable, ZfcAxiom};
    use naome_ledger::ProofBatchError;

    use super::*;
    use crate::{PendingBudget, StaticPeer};

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
        let local = crate::Keypair::generate_ed25519();
        let address = "/ip4/127.0.0.1/tcp/9".parse().unwrap();
        StaticProofNetwork::new(local, [StaticPeer::new(remote_peer_id, address)]).unwrap()
    }

    fn response_for(
        network: &mut StaticProofNetwork,
        acquisition: &ProofDependencyAcquisition,
        bytes: Vec<u8>,
    ) -> ReceivedProofResponse {
        let request_id = acquisition.pending_request_id;
        let pending = network
            .pending
            .remove(&request_id)
            .expect("the acquisition request is pending");
        ReceivedProofResponse {
            request_id,
            peer_id: pending.peer_id,
            request: pending.request,
            response: ProofResponse::from_wire_bytes(bytes).unwrap(),
            _permit: pending._permit,
        }
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
            .on_response(&mut network, &selected, response)
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
                .on_response(&mut network, &selected, response)
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
            acquisition.on_response(&mut network, &selected, response),
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
            acquisition.on_response(&mut network, &selected, response),
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
            .on_response(&mut network, &selected, response)
            .unwrap()
        else {
            panic!("maximum closure did not request its dependencies");
        };

        let closure = loop {
            let response = response_for(&mut network, &acquisition, pairing_bytes());
            match acquisition
                .on_response(&mut network, &selected, response)
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
            .on_response(&mut network, &selected, response)
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
            .on_response(&mut network, &selected, response)
            .unwrap()
        else {
            panic!("shared dependency was not requested");
        };
        assert_eq!(acquisition.pending_request().proof_id(), shared);
        let response = response_for(&mut network, &acquisition, pairing_bytes());
        let DependencyAcquisitionProgress::Complete(closure) = acquisition
            .on_response(&mut network, &selected, response)
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
            .on_response(&mut network, &selected, response)
            .unwrap()
        else {
            panic!("dependency was not requested");
        };
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 2);
        let response = response_for(&mut network, &acquisition, Vec::new());
        assert!(matches!(
            acquisition.on_response(&mut network, &selected, response),
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
            self_acquisition.on_response(&mut self_network, &selected, self_response),
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
            .on_response(&mut network, &selected, response)
            .unwrap()
        else {
            panic!("two-node cycle did not request its second node");
        };
        assert_eq!(acquisition.pending_request().proof_id(), child);
        let response = response_for(&mut network, &acquisition, reference_closure_bytes(&[root]));
        assert!(matches!(
            acquisition.on_response(&mut network, &selected, response),
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
        assert!(!current.accepts_response(&stale));
        assert_eq!(current.pending_request().proof_id(), requested);
        drop(stale);
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);

        let response = response_for(&mut network, &current, pairing_bytes());
        let DependencyAcquisitionProgress::Complete(closure) = current
            .on_response(&mut network, &selected, response)
            .unwrap()
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
        assert!(!current.accepts_response(&stale_unavailable));
        assert!(matches!(
            current.on_response(&mut network, &selected, stale_unavailable),
            Err(DependencyAcquisitionError::UnexpectedResponse)
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
        assert!(acquisition.accepts_response(&response));

        assert!(matches!(
            acquisition.on_response(&mut wrong_driver, &selected, response),
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

        assert!(!acquisition.accepts_response(&other_response));
        assert!(matches!(
            acquisition.on_response(&mut origin, &selected, other_response),
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
            .on_response(&mut network, &selected, response)
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
            .on_response(&mut network, &selected, response)
            .unwrap()
        else {
            panic!("root dependency was not requested");
        };
        let response = response_for(&mut network, &acquisition, parent_bytes.clone());
        let DependencyAcquisitionProgress::Complete(closure) = acquisition
            .on_response(&mut network, &selected, response)
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
}
