//! Content-addressed in-memory state for the NAOME proof DAG.
//!
//! Each admitted node is exactly one canonical Foundation V0 proof. Its
//! [`ProofId`] is the node address and its checked external proof references
//! are the outgoing dependency edges. Admission delegates all decoding,
//! canonicality, mathematical checking, and identity validation to
//! [`LedgerStateV0`] before retaining the resulting record.
//!
//! This crate defines neither a linear proof parent nor consensus, finality,
//! persistence, economy, or peer-to-peer synchronization.

use std::collections::{BTreeMap, btree_map::Entry};

use naome_ledger::{AcceptedProofRecordV0, LedgerError, LedgerStateV0};
use naome_proof::ProofId;

/// A selected, monotonically growing set of accepted proof-DAG nodes.
///
/// Both the checked resolver state and retained records are private so callers
/// cannot insert unverified bytes, identities, or dependency edges.
#[derive(Default)]
#[must_use]
pub struct ProofDagV0 {
    ledger: LedgerStateV0,
    records: BTreeMap<ProofId, AcceptedProofRecordV0>,
}

impl ProofDagV0 {
    /// Constructs an empty proof DAG.
    pub const fn new() -> Self {
        Self {
            ledger: LedgerStateV0::new(),
            records: BTreeMap::new(),
        }
    }

    /// Returns the number of retained proof nodes.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns whether no proof nodes have been retained.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Returns one locally accepted proof record by its content address.
    pub fn proof(&self, proof_id: ProofId) -> Option<&AcceptedProofRecordV0> {
        self.records.get(&proof_id)
    }

    /// Strictly admits and retains one canonical proof node.
    ///
    /// Every direct dependency must already belong to this selected state. A
    /// failure leaves both the checked ledger and retained-record index
    /// unchanged.
    pub fn apply_canonical_proof_bytes(
        &mut self,
        bytes: Vec<u8>,
    ) -> Result<&AcceptedProofRecordV0, LedgerError> {
        let record = self.ledger.apply_canonical_proof_bytes(bytes)?;
        let proof_id = record.proof_id();

        match self.records.entry(proof_id) {
            Entry::Vacant(entry) => Ok(entry.insert(record)),
            Entry::Occupied(_) => {
                unreachable!("private ledger and retained proof indexes stay aligned")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use naome_checker::{CheckError, ProofStateError};
    use naome_foundation::{Formula, FreeVariable, LogicError, ZfcAxiom};
    use naome_ledger::LedgerError;
    use naome_proof::{ProofCertificateV0, ProofId, ProofStepV0};

    use super::ProofDagV0;

    fn certificate(steps: Vec<ProofStepV0>) -> ProofCertificateV0 {
        ProofCertificateV0::new(steps).unwrap()
    }

    fn canonical_bytes(steps: Vec<ProofStepV0>) -> Vec<u8> {
        certificate(steps)
            .into_unchecked_normal_form()
            .canonical_bytes()
            .to_vec()
    }

    fn axiom_bytes(axiom: ZfcAxiom) -> Vec<u8> {
        canonical_bytes(vec![ProofStepV0::ZfcAxiom(axiom)])
    }

    fn referenced_generalization(proof_id: ProofId, variable: FreeVariable) -> Vec<u8> {
        canonical_bytes(vec![
            ProofStepV0::ProofReference { proof_id },
            ProofStepV0::Generalization {
                premise: 0,
                variable,
            },
        ])
    }

    fn identity_bytes(variable: FreeVariable) -> Vec<u8> {
        canonical_bytes(vec![
            ProofStepV0::EqualityReflexivity { variable },
            ProofStepV0::Generalization {
                premise: 0,
                variable,
            },
        ])
    }

    fn identity_detour_bytes(variable: FreeVariable) -> Vec<u8> {
        let equality = Formula::equal(variable, variable);
        canonical_bytes(vec![
            ProofStepV0::EqualityReflexivity { variable },
            ProofStepV0::Simplification {
                antecedent: equality.clone(),
                consequent: equality,
            },
            ProofStepV0::ModusPonens {
                premise: 0,
                implication: 1,
            },
            ProofStepV0::ModusPonens {
                premise: 0,
                implication: 2,
            },
            ProofStepV0::Generalization {
                premise: 3,
                variable,
            },
        ])
    }

    fn proof_citing_both_identities(
        direct: ProofId,
        detour: ProofId,
        variable: FreeVariable,
    ) -> Vec<u8> {
        let equality = Formula::equal(variable, variable);
        let identity = Formula::for_all(variable, equality);
        canonical_bytes(vec![
            ProofStepV0::ProofReference { proof_id: direct },
            ProofStepV0::ProofReference { proof_id: detour },
            ProofStepV0::Simplification {
                antecedent: identity.clone(),
                consequent: identity,
            },
            ProofStepV0::ModusPonens {
                premise: 1,
                implication: 2,
            },
            ProofStepV0::ModusPonens {
                premise: 0,
                implication: 3,
            },
        ])
    }

    #[test]
    fn independent_nodes_have_no_implicit_linear_order() {
        let pairing = axiom_bytes(ZfcAxiom::Pairing);
        let union = axiom_bytes(ZfcAxiom::Union);
        let unknown = ProofId::from_bytes([0x55; 32]);
        let mut first = ProofDagV0::new();

        assert!(first.is_empty());
        assert!(first.proof(unknown).is_none());
        let pairing_id = first
            .apply_canonical_proof_bytes(pairing.clone())
            .unwrap()
            .proof_id();
        let union_id = first
            .apply_canonical_proof_bytes(union.clone())
            .unwrap()
            .proof_id();
        assert_eq!(first.len(), 2);
        assert!(
            first
                .proof(pairing_id)
                .unwrap()
                .direct_dependencies()
                .is_empty()
        );
        assert!(
            first
                .proof(union_id)
                .unwrap()
                .direct_dependencies()
                .is_empty()
        );

        let mut reversed = ProofDagV0::new();
        let _ = reversed.apply_canonical_proof_bytes(union).unwrap();
        let _ = reversed.apply_canonical_proof_bytes(pairing).unwrap();
        assert_eq!(reversed.proof(pairing_id), first.proof(pairing_id));
        assert_eq!(reversed.proof(union_id), first.proof(union_id));
    }

    #[test]
    fn dependencies_must_precede_admission_and_replay_directly() {
        let root_bytes = axiom_bytes(ZfcAxiom::Pairing);
        let mut original = ProofDagV0::new();
        let root_id = original
            .apply_canonical_proof_bytes(root_bytes.clone())
            .unwrap()
            .proof_id();
        let child_bytes = referenced_generalization(root_id, FreeVariable::new(0));
        let child_id = original
            .apply_canonical_proof_bytes(child_bytes.clone())
            .unwrap()
            .proof_id();
        let grandchild_bytes = referenced_generalization(child_id, FreeVariable::new(1));
        let grandchild_id = original
            .apply_canonical_proof_bytes(grandchild_bytes.clone())
            .unwrap()
            .proof_id();

        assert_eq!(
            original.proof(child_id).unwrap().direct_dependencies(),
            [root_id]
        );
        assert_eq!(
            original.proof(grandchild_id).unwrap().direct_dependencies(),
            [child_id]
        );
        assert!(
            !original
                .proof(grandchild_id)
                .unwrap()
                .direct_dependencies()
                .contains(&root_id)
        );

        let mut replay = ProofDagV0::new();
        assert_eq!(
            replay.apply_canonical_proof_bytes(child_bytes.clone()),
            Err(LedgerError::Check {
                source: CheckError::UnknownProofReference {
                    step: 0,
                    proof_id: root_id,
                },
            })
        );
        assert!(replay.is_empty());

        let _ = replay.apply_canonical_proof_bytes(root_bytes).unwrap();
        let _ = replay.apply_canonical_proof_bytes(child_bytes).unwrap();
        let _ = replay
            .apply_canonical_proof_bytes(grandchild_bytes)
            .unwrap();
        assert_eq!(replay.proof(root_id), original.proof(root_id));
        assert_eq!(replay.proof(child_id), original.proof(child_id));
        assert_eq!(replay.proof(grandchild_id), original.proof(grandchild_id));
    }

    #[test]
    fn duplicate_artifacts_and_reference_aliases_never_overwrite_records() {
        let root_bytes = axiom_bytes(ZfcAxiom::Pairing);
        let mut dag = ProofDagV0::new();
        let root = dag.apply_canonical_proof_bytes(root_bytes.clone()).unwrap();
        let root_id = root.proof_id();
        let derivation_id = root.derivation_id();

        assert_eq!(
            dag.apply_canonical_proof_bytes(root_bytes),
            Err(LedgerError::State {
                source: ProofStateError::DuplicateProof { proof_id: root_id },
            })
        );
        assert_eq!(dag.len(), 1);

        let alias = canonical_bytes(vec![ProofStepV0::ProofReference { proof_id: root_id }]);
        assert_eq!(
            dag.apply_canonical_proof_bytes(alias),
            Err(LedgerError::State {
                source: ProofStateError::DuplicateDerivation { derivation_id },
            })
        );
        assert_eq!(dag.len(), 1);
        assert_eq!(dag.proof(root_id).unwrap().proof_id(), root_id);
    }

    #[test]
    fn genuine_alternative_derivations_of_one_statement_are_retained() {
        let variable = FreeVariable::new(7);
        let mut dag = ProofDagV0::new();
        let direct_id = dag
            .apply_canonical_proof_bytes(identity_bytes(variable))
            .unwrap()
            .proof_id();
        let detour_id = dag
            .apply_canonical_proof_bytes(identity_detour_bytes(variable))
            .unwrap()
            .proof_id();
        let direct = dag.proof(direct_id).unwrap();
        let detour = dag.proof(detour_id).unwrap();

        assert_eq!(direct.statement_id(), detour.statement_id());
        assert_ne!(direct.derivation_id(), detour.derivation_id());
        assert_ne!(direct.proof_id(), detour.proof_id());

        let dependent_id = dag
            .apply_canonical_proof_bytes(proof_citing_both_identities(
                direct_id, detour_id, variable,
            ))
            .unwrap()
            .proof_id();
        assert_eq!(
            dag.proof(dependent_id).unwrap().direct_dependencies(),
            [direct_id, detour_id]
        );
        assert_eq!(dag.len(), 3);
    }

    #[test]
    fn unrelated_prior_nodes_do_not_change_an_accepted_record() {
        let root_bytes = axiom_bytes(ZfcAxiom::Pairing);
        let mut minimal = ProofDagV0::new();
        let root_id = minimal
            .apply_canonical_proof_bytes(root_bytes.clone())
            .unwrap()
            .proof_id();
        let child_bytes = referenced_generalization(root_id, FreeVariable::new(0));
        let child_id = minimal
            .apply_canonical_proof_bytes(child_bytes.clone())
            .unwrap()
            .proof_id();

        let mut extended = ProofDagV0::new();
        let _ = extended.apply_canonical_proof_bytes(root_bytes).unwrap();
        let _ = extended
            .apply_canonical_proof_bytes(axiom_bytes(ZfcAxiom::Union))
            .unwrap();
        let _ = extended.apply_canonical_proof_bytes(child_bytes).unwrap();

        assert_eq!(minimal.proof(child_id), extended.proof(child_id));
    }

    #[test]
    fn failed_boundaries_leave_the_retained_dag_unchanged() {
        let mut dag = ProofDagV0::new();
        let root_bytes = axiom_bytes(ZfcAxiom::Pairing);
        let root_id = dag
            .apply_canonical_proof_bytes(root_bytes.clone())
            .unwrap()
            .proof_id();
        let assert_root_unchanged = |dag: &ProofDagV0| {
            assert_eq!(dag.len(), 1);
            assert_eq!(
                dag.proof(root_id).unwrap().canonical_proof_bytes(),
                root_bytes
            );
        };

        assert!(matches!(
            dag.apply_canonical_proof_bytes(vec![0]),
            Err(LedgerError::Decode { .. })
        ));
        assert_root_unchanged(&dag);

        let noncanonical = certificate(vec![
            ProofStepV0::ZfcAxiom(ZfcAxiom::Pairing),
            ProofStepV0::ZfcAxiom(ZfcAxiom::Union),
        ])
        .to_canonical_bytes();
        assert_eq!(
            dag.apply_canonical_proof_bytes(noncanonical),
            Err(LedgerError::NonCanonicalProof)
        );
        assert_root_unchanged(&dag);

        let invalid = canonical_bytes(vec![
            ProofStepV0::ZfcAxiom(ZfcAxiom::Pairing),
            ProofStepV0::ZfcAxiom(ZfcAxiom::Union),
            ProofStepV0::ModusPonens {
                premise: 0,
                implication: 1,
            },
        ]);
        assert_eq!(
            dag.apply_canonical_proof_bytes(invalid),
            Err(LedgerError::Check {
                source: CheckError::Logic {
                    step: 2,
                    source: LogicError::ModusPonensMismatch,
                },
            })
        );
        assert_root_unchanged(&dag);

        let missing = ProofId::from_bytes([0x77; 32]);
        assert_eq!(
            dag.apply_canonical_proof_bytes(referenced_generalization(
                missing,
                FreeVariable::new(1),
            )),
            Err(LedgerError::Check {
                source: CheckError::UnknownProofReference {
                    step: 0,
                    proof_id: missing,
                },
            })
        );
        assert_root_unchanged(&dag);

        let child = dag
            .apply_canonical_proof_bytes(referenced_generalization(root_id, FreeVariable::new(2)))
            .unwrap();
        assert_eq!(child.direct_dependencies(), [root_id]);
        assert_eq!(dag.len(), 2);
    }
}
