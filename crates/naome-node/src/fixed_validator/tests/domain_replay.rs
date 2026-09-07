//! Exact-binding replay vectors for every currently supported signed role.
//! Correctly signed foreign evidence is distinct from malformed input.

use super::driver::fixed_branch;
use super::*;
use naome_consensus::{
    ActiveAgreementSnapshot, ConsensusHeight, ConsensusVoteRole as Role,
    ConsensusVoteTarget as Target, FixedValidatorLockPhaseV0 as Phase, VerifiedConsensusVoteV0,
    VerifiedFixedConsensusProposalV0, VerifiedQuorumCertificateV0,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Change {
    Chain,
    Genesis,
    Version,
    Role,
    Domain,
    Height,
    Round,
    Target,
    Root,
}

const CHANGES: [Change; 9] = [
    Change::Chain,
    Change::Genesis,
    Change::Version,
    Change::Role,
    Change::Domain,
    Change::Height,
    Change::Round,
    Change::Target,
    Change::Root,
];

fn foreign_context(context: ConsensusContextV0, change: Change) -> ConsensusContextV0 {
    ConsensusContextV0::new(
        if change == Change::Chain {
            naome_chain::ArtifactChainId::from_bytes([0xaa; 32])
        } else {
            context.chain_id()
        },
        if change == Change::Genesis {
            ConsensusGenesisId::from_bytes([0xbb; 32])
        } else {
            context.genesis_id()
        },
        if change == Change::Version {
            ConsensusProtocolVersion::new(8)
        } else {
            context.protocol_version()
        },
    )
}

fn foreign_position(position: ConsensusPosition, change: Change) -> ConsensusPosition {
    ConsensusPosition::new(
        ConsensusHeight::new(position.height().value() + u64::from(change == Change::Height)),
        ConsensusRound::new(position.round().value() + u64::from(change == Change::Round)),
    )
}

fn role_domain(role: Role) -> &'static [u8] {
    match role {
        Role::Prevote => b"naome:consensus-prevote-signing:v0\0",
        Role::Precommit => b"naome:consensus-precommit-signing:v0\0",
    }
}

fn other_role(role: Role) -> Role {
    match role {
        Role::Prevote => Role::Precommit,
        Role::Precommit => Role::Prevote,
    }
}

fn snapshot(fixture: &Fixture, position: ConsensusPosition) -> ActiveAgreementSnapshot {
    ActiveAgreementSnapshot::try_from_preselected(position, &fixture.entries).unwrap()
}

fn proposal(value: ConsensusValueV0, authorization: &[u8]) -> Vec<u8> {
    let mut bytes = value.to_canonical_bytes().to_vec();
    bytes.extend_from_slice(authorization);
    bytes.push(VerifiedFixedConsensusProposalV0::NO_VALID_ROUND_PROOF_TAG);
    bytes
}

fn rejected_vote<'node>(
    outcome: FixedValidatorNodeVoteExecutionOutcomeV0<'node>,
) -> FixedValidatorNodeSigningScopeV0<'node> {
    match outcome {
        FixedValidatorNodeVoteExecutionOutcomeV0::Rejected { scope, .. } => *scope,
        _ => panic!("foreign evidence must reject before signing"),
    }
}

fn signed_vote<'node>(
    outcome: FixedValidatorNodeVoteExecutionOutcomeV0<'node>,
) -> FixedValidatorNodeSigningScopeV0<'node> {
    match outcome {
        FixedValidatorNodeVoteExecutionOutcomeV0::Signed { scope, .. } => *scope,
        _ => panic!("positive local evidence must sign"),
    }
}

fn unchanged(
    scope: &mut FixedValidatorNodeSigningScopeV0<'_>,
    layout: &TestLayout,
    before: &[Vec<(String, Vec<u8>)>; 4],
    position: ConsensusPosition,
    phase: Phase,
) {
    assert_eq!(&layout.images(), before);
    assert_eq!(scope.signing_session().position(), position);
    assert_eq!(scope.signing_session().phase(), phase);
    assert!(scope.signing_session().locked_value().is_none());
    assert!(scope.signing_session().valid_value().is_none());
    assert_eq!(scope.finality().finalized_len().unwrap(), 0);
}

#[test]
fn producer_authorization_replay_matrix_preserves_exact_node_state_before_positive_prevote() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("producer-domain-replay");
    fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap()
        .run_with_signing_session(|mut scope| {
            let branch = scope.branch().clone();
            let round = branch.begin_round_zero().unwrap();
            let payload = proof_payload(ZfcAxiom::Pairing);
            let block = ArtifactChainState::new(fixture.definition)
                .prepare_block(artifact_id(&payload))
                .unwrap();
            let value = round.value_for_artifact_block(block);
            let position = round.position();
            let root = value.proposal_signing_root();
            let original =
                authorization_bytes(fixture.context, position, root, &fixture.signing_key());
            let before = layout.images();
            for change in CHANGES {
                if change == Change::Root {
                    continue;
                } // Authorization has one non-nil root form.
                let context = foreign_context(fixture.context, change);
                let foreign = foreign_position(position, change);
                let expected_root = if change == Change::Target {
                    ProposalSigningRoot::from_bytes([0xcc; 32])
                } else {
                    root
                };
                let mut bytes =
                    authorization_bytes(context, foreign, expected_root, &fixture.signing_key());
                if matches!(change, Change::Role | Change::Domain) {
                    let domain = if change == Change::Role {
                        role_domain(Role::Prevote)
                    } else {
                        role_domain(Role::Precommit)
                    };
                    let mut transcript = domain.to_vec();
                    transcript.extend_from_slice(&bytes[..148]);
                    let signature = fixture.signing_key().sign(&transcript);
                    fixture
                        .signing_key()
                        .verifying_key()
                        .verify_strict(&transcript, &signature)
                        .unwrap();
                    bytes[148..].copy_from_slice(&signature.to_bytes());
                    assert!(
                        VerifiedProducerAuthorizationV0::decode_and_verify(
                            &bytes,
                            context,
                            fixture.entries[0].consensus_key(),
                            &snapshot(&fixture, foreign)
                        )
                        .is_err()
                    );
                } else {
                    let own_snapshot = snapshot(&fixture, foreign);
                    let verified = VerifiedProducerAuthorizationV0::decode_and_verify(
                        &bytes,
                        context,
                        fixture.entries[0].consensus_key(),
                        &own_snapshot,
                    )
                    .unwrap();
                    assert_eq!(verified.proposal_signing_root(), expected_root);
                }
                let control = proposal(value, &bytes);
                assert!(
                    round
                        .decode_and_verify_proposal_control(&control, payload.clone())
                        .is_err(),
                    "{change:?}"
                );
                scope = rejected_vote(
                    scope
                        .sign_prevote_for_proposal(
                            &control,
                            payload.clone(),
                            ConsensusRound::new(0),
                        )
                        .unwrap(),
                );
                unchanged(&mut scope, &layout, &before, position, Phase::Proposal);
            }
            let control = proposal(value, &original);
            let _ = round
                .decode_and_verify_proposal_control(&control, payload.clone())
                .unwrap();
            let mut scope = signed_vote(
                scope
                    .sign_prevote_for_proposal(&control, payload, ConsensusRound::new(0))
                    .unwrap(),
            );
            assert_eq!(scope.signing_session().phase(), Phase::Prevote);
            assert_ne!(layout.images(), before);
            assert_eq!(layout.images()[..2], before[..2]);
        })
        .unwrap();
}

fn vote(
    fixture: &Fixture,
    position: ConsensusPosition,
    role: Role,
    target: Target,
    change: Option<Change>,
) -> (Vec<u8>, Vec<u8>) {
    let context = change.map_or(fixture.context, |c| foreign_context(fixture.context, c));
    let position = change.map_or(position, |c| foreign_position(position, c));
    let role = if change == Some(Change::Role) {
        other_role(role)
    } else {
        role
    };
    let target = if change == Some(Change::Root) {
        Target::Proposal(ProposalSigningRoot::from_bytes([0xdd; 32]))
    } else if change == Some(Change::Target) {
        match target {
            Target::Nil => Target::Proposal(ProposalSigningRoot::from_bytes([0xdd; 32])),
            Target::Proposal(_) => Target::Nil,
        }
    } else {
        target
    };
    let mut body = [0_u8; VOTE_BODY_BYTES];
    body[0] = match role {
        Role::Prevote => 1,
        Role::Precommit => 2,
    };
    body[1..33].copy_from_slice(context.chain_id().as_bytes());
    body[33..65].copy_from_slice(context.genesis_id().as_bytes());
    body[65..69].copy_from_slice(&context.protocol_version().value().to_be_bytes());
    body[69..77].copy_from_slice(&position.height().value().to_be_bytes());
    body[77..85].copy_from_slice(&position.round().value().to_be_bytes());
    if let Target::Proposal(root) = target {
        body[85] = 1;
        body[86..].copy_from_slice(root.as_bytes());
    }
    let domain = role_domain(if change == Some(Change::Domain) {
        other_role(role)
    } else {
        role
    });
    let mut transcript = domain.to_vec();
    transcript.extend_from_slice(&body);
    transcript.extend_from_slice(fixture.entries[0].consensus_key().as_bytes());
    let signature = fixture.signing_key().sign(&transcript);
    fixture
        .signing_key()
        .verifying_key()
        .verify_strict(&transcript, &signature)
        .unwrap();
    let mut signed = body.to_vec();
    signed.extend_from_slice(fixture.entries[0].consensus_key().as_bytes());
    signed.extend_from_slice(&signature.to_bytes());
    let mut certificate = body.to_vec();
    certificate.extend_from_slice(&1_u16.to_be_bytes());
    certificate.extend_from_slice(&signed[VOTE_BODY_BYTES..]);
    let own_snapshot = snapshot(fixture, position);
    if change == Some(Change::Domain) {
        assert!(VerifiedConsensusVoteV0::decode_and_verify(&signed, context).is_err());
        assert!(
            VerifiedQuorumCertificateV0::decode_and_verify(&certificate, context, &own_snapshot)
                .is_err()
        );
    } else {
        let verified = VerifiedConsensusVoteV0::decode_and_verify(&signed, context).unwrap();
        assert_eq!(verified.role(), role);
        assert_eq!(verified.target(), target);
        let _ =
            VerifiedQuorumCertificateV0::decode_and_verify(&certificate, context, &own_snapshot)
                .unwrap();
    }
    (signed, certificate)
}

#[test]
fn agreement_certificate_and_signed_batch_replay_matrix_preserves_state_for_all_roles_and_targets()
{
    for role in [Role::Prevote, Role::Precommit] {
        for nil in [false, true] {
            for batch in [false, true] {
                let fixture = Fixture::new();
                let layout = TestLayout::new("agreement-domain-replay");
                fixture.provision(&layout, 8).create(fixture.signing_key()).unwrap()
                    .run_with_signing_session(|mut scope| {
                        let branch = scope.branch().clone();
                        let round = branch.begin_round_zero().unwrap();
                        let position = round.position();
                        let payload = proof_payload(ZfcAxiom::Pairing);
                        let block = ArtifactChainState::new(fixture.definition).prepare_block(artifact_id(&payload)).unwrap();
                        let value = round.value_for_artifact_block(block);
                        let root = value.proposal_signing_root();
                        let control = proposal(value, &authorization_bytes(fixture.context, position, root, &fixture.signing_key()));
                        let target = if nil { Target::Nil } else { Target::Proposal(root) };
                        // Put signing/round-close routes in their legitimate
                        // source phase; finality remains phase-independent.
                        if role == Role::Prevote || nil {
                            scope = signed_vote(scope.sign_prevote_after_proposal_close(fixture.context, position, ConsensusRound::new(0)).unwrap());
                        }
                        if role == Role::Precommit && nil {
                            scope = signed_vote(scope.sign_precommit_after_prevote_close(fixture.context, position, ConsensusRound::new(0)).unwrap());
                        }
                        let phase = scope.signing_session().phase();
                        let before = layout.images();
                        for change in CHANGES {
                            if nil && change == Change::Root { continue; }
                            let (signed, certificate) = vote(&fixture, position, role, target, Some(change));
                            assert!(round.build_quorum_certificate_from_signed_votes(&[&signed], role, target).is_err(), "{role:?} {target:?} {change:?}");
                            scope = match (role, nil) {
                                (Role::Prevote, _) => {
                                    let outcome = if nil {
                                        if batch { scope.sign_precommit_for_nil_vote_batch(&[&signed], ConsensusRound::new(0)) }
                                        else { scope.sign_precommit_for_nil_quorum(&certificate, ConsensusRound::new(0)) }
                                    } else if batch {
                                        scope.sign_precommit_for_proposal_vote_batch(&control, payload.clone(), &[&signed], ConsensusRound::new(0))
                                    } else {
                                        scope.sign_precommit_for_proposal_quorum(&control, payload.clone(), &certificate, ConsensusRound::new(0))
                                    };
                                    rejected_vote(outcome.unwrap())
                                }
                                (Role::Precommit, true) => {
                                    let outcome = if batch { scope.advance_round_for_nil_precommit_vote_batch(&[&signed], ConsensusRound::new(1)) }
                                        else { scope.advance_round_for_nil_precommit_quorum(&certificate, ConsensusRound::new(1)) };
                                    match outcome.unwrap() {
                                        FixedValidatorNodeRoundAdvanceOutcomeV0::Rejected { scope, .. } => *scope,
                                        _ => panic!("foreign nil precommit must not advance the round"),
                                    }
                                }
                                (Role::Precommit, false) => {
                                    let outcome = if batch { scope.commit_current_round_finality_vote_batch(&control, payload.clone(), &[&signed], ConsensusRound::new(0)) }
                                        else { scope.commit_current_round_finality(&control, payload.clone(), &certificate, ConsensusRound::new(0)) };
                                    match outcome.unwrap() {
                                        FixedValidatorNodeCurrentRoundFinalityOutcomeV0::Rejected { scope, .. } => *scope,
                                        _ => panic!("foreign precommit must not finalize"),
                                    }
                                }
                            };
                            unchanged(&mut scope, &layout, &before, position, phase);
                        }
                        let (signed, certificate) = vote(&fixture, position, role, target, None);
                        assert_eq!(round.build_quorum_certificate_from_signed_votes(&[&signed], role, target).unwrap().to_canonical_bytes(), certificate);
                        match (role, nil) {
                            (Role::Prevote, _) => {
                                let outcome = if nil {
                                    if batch { scope.sign_precommit_for_nil_vote_batch(&[&signed], ConsensusRound::new(0)) }
                                    else { scope.sign_precommit_for_nil_quorum(&certificate, ConsensusRound::new(0)) }
                                } else if batch { scope.sign_precommit_for_proposal_vote_batch(&control, payload, &[&signed], ConsensusRound::new(0)) }
                                else { scope.sign_precommit_for_proposal_quorum(&control, payload, &certificate, ConsensusRound::new(0)) };
                                let mut scope = signed_vote(outcome.unwrap());
                                assert_eq!(scope.signing_session().phase(), Phase::Precommit);
                                assert_eq!(scope.signing_session().locked_value().is_some(), !nil);
                                assert_eq!(scope.signing_session().valid_value().is_some(), !nil);
                                assert_ne!(layout.images(), before);
                                assert_eq!(layout.images()[..2], before[..2]);
                            }
                            (Role::Precommit, true) => {
                                let outcome = if batch { scope.advance_round_for_nil_precommit_vote_batch(&[&signed], ConsensusRound::new(1)) }
                                    else { scope.advance_round_for_nil_precommit_quorum(&certificate, ConsensusRound::new(1)) };
                                let FixedValidatorNodeRoundAdvanceOutcomeV0::Advanced { mut scope, .. } = outcome.unwrap() else { panic!("valid nil quorum") };
                                assert_eq!(scope.signing_session().position().round(), ConsensusRound::new(1));
                                assert_eq!(scope.signing_session().phase(), Phase::Proposal);
                                assert_eq!(layout.images(), before);
                            }
                            (Role::Precommit, false) => {
                                let outcome = if batch { scope.commit_current_round_finality_vote_batch(&control, payload, &[&signed], ConsensusRound::new(0)) }
                                    else { scope.commit_current_round_finality(&control, payload, &certificate, ConsensusRound::new(0)) };
                                let FixedValidatorNodeCurrentRoundFinalityOutcomeV0::Finality(FixedValidatorNodeFinalityOutcomeV0::Continues { mut scope, .. }) = outcome.unwrap() else { panic!("valid proposal finality") };
                                assert_eq!(scope.signing_session().position().height().value(), 2);
                                assert_eq!(scope.finality().finalized_len().unwrap(), 1);
                            }
                        }
                    }).unwrap();
            }
        }
    }
}

#[test]
fn retained_proposal_proof_replay_matrix_rejects_before_prevote_and_accepts_exact_earlier_proof() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("retained-proof-domain-replay");
    fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap()
        .run_with_signing_session(|mut scope| {
            let branch = scope.branch().clone();
            let zero = branch.begin_round_zero().unwrap();
            let original_position = zero.position();
            scope = signed_vote(
                scope
                    .sign_prevote_after_proposal_close(
                        fixture.context,
                        original_position,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            scope = signed_vote(
                scope
                    .sign_precommit_after_prevote_close(
                        fixture.context,
                        original_position,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            scope = match scope
                .advance_round_after_precommit_close(
                    fixture.context,
                    original_position,
                    ConsensusRound::new(1),
                )
                .unwrap()
            {
                FixedValidatorNodeRoundAdvanceOutcomeV0::Advanced { scope, .. } => *scope,
                _ => panic!("ordinary next round"),
            };
            let one = zero.advance_round().unwrap();
            let position = one.position();
            let payload = proof_payload(ZfcAxiom::Pairing);
            let block = ArtifactChainState::new(fixture.definition)
                .prepare_block(artifact_id(&payload))
                .unwrap();
            let value = one.value_for_artifact_block(block);
            let root = value.proposal_signing_root();
            let mut prefix = proposal(
                value,
                &authorization_bytes(fixture.context, position, root, &fixture.signing_key()),
            );
            *prefix.last_mut().unwrap() = VerifiedFixedConsensusProposalV0::VALID_ROUND_PROOF_TAG;
            let before = layout.images();
            for change in CHANGES {
                let (_, certificate) = vote(
                    &fixture,
                    original_position,
                    Role::Prevote,
                    Target::Proposal(root),
                    Some(change),
                );
                let mut control = prefix.clone();
                control.extend_from_slice(&certificate);
                assert!(
                    one.decode_and_verify_proposal_control(&control, payload.clone())
                        .is_err(),
                    "{change:?}"
                );
                scope = rejected_vote(
                    scope
                        .sign_prevote_for_proposal(
                            &control,
                            payload.clone(),
                            ConsensusRound::new(1),
                        )
                        .unwrap(),
                );
                unchanged(&mut scope, &layout, &before, position, Phase::Proposal);
            }
            let (_, certificate) = vote(
                &fixture,
                original_position,
                Role::Prevote,
                Target::Proposal(root),
                None,
            );
            prefix.extend_from_slice(&certificate);
            let verified = one
                .decode_and_verify_proposal_control(&prefix, payload.clone())
                .unwrap();
            assert_eq!(
                verified.valid_round_certificate_bytes(),
                Some(certificate.as_slice())
            );
            let mut scope = signed_vote(
                scope
                    .sign_prevote_for_proposal(&prefix, payload, ConsensusRound::new(1))
                    .unwrap(),
            );
            assert_eq!(scope.signing_session().phase(), Phase::Prevote);
            assert_eq!(layout.images()[..2], before[..2]);
            assert_ne!(layout.images(), before);
        })
        .unwrap();
}

#[test]
fn fully_valid_foreign_proposals_and_finality_envelopes_reject_without_authority_or_custody() {
    let fixture = Fixture::new();
    for dimension in [Change::Chain, Change::Genesis, Change::Version] {
        let mut foreign = Fixture::new();
        if dimension == Change::Chain {
            foreign.definition = ArtifactChainDefinition::new([0xea; 32]);
        }
        foreign.context = ConsensusContextV0::new(
            foreign.definition.id(),
            if dimension == Change::Genesis {
                ConsensusGenesisId::from_bytes([0xeb; 32])
            } else {
                foreign.context.genesis_id()
            },
            if dimension == Change::Version {
                ConsensusProtocolVersion::new(8)
            } else {
                foreign.context.protocol_version()
            },
        );
        let foreign_branch = fixed_branch(&foreign);
        let round = foreign_branch.begin_round_zero().unwrap();
        let payload = proof_payload(ZfcAxiom::Pairing);
        let block = ArtifactChainState::new(foreign.definition)
            .prepare_block(artifact_id(&payload))
            .unwrap();
        let value = round.value_for_artifact_block(block);
        let control = proposal(
            value,
            &authorization_bytes(
                foreign.context,
                round.position(),
                value.proposal_signing_root(),
                &foreign.signing_key(),
            ),
        );
        let (_, certificate) = vote(
            &foreign,
            round.position(),
            Role::Precommit,
            Target::Proposal(value.proposal_signing_root()),
            None,
        );
        let proof = round
            .decode_and_verify_proposal_control(&control, payload.clone())
            .unwrap()
            .seal_with_precommit_certificate(&certificate)
            .unwrap()
            .into_owned();
        let layout = TestLayout::new("foreign-control-and-envelope");
        fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap()
            .run_with_signing_session(|scope| {
                let before = layout.images();
                let mut scope = rejected_vote(
                    scope
                        .sign_prevote_for_proposal(
                            &control,
                            payload.clone(),
                            ConsensusRound::new(0),
                        )
                        .unwrap(),
                );
                let position = scope.signing_session().position();
                unchanged(&mut scope, &layout, &before, position, Phase::Proposal);
                // This adapter independently derives the live direct-child
                // expectation; it cannot borrow the foreign proof's context.
                let driver = super::driver::driver(scope, 8, 8);
                let (driver, _) = super::driver::step_arm(driver);
                let driver = match driver
                    .commit_finality_envelope(
                        proof.canonical_envelope_bytes(),
                        proof.canonical_artifact_bytes().to_vec(),
                    )
                    .unwrap()
                {
                    FixedValidatorNodeDriverEnvelopeOutcomeV0::Rejected { driver, .. } => *driver,
                    _ => panic!("foreign complete proof must reject"),
                };
                assert_eq!(driver.position(), position);
                assert_eq!(driver.phase(), Phase::Proposal);
                assert!(!driver.has_pending_command());
                assert_eq!(
                    driver.inbox_len()
                        + driver.current_inbox_len()
                        + driver.current_finality_inbox_len()
                        + driver.current_nil_precommit_inbox_len(),
                    0
                );
                assert_eq!(layout.images(), before);
                let local = fixture.transition(
                    &fixed_branch(&fixture),
                    &ArtifactChainState::new(fixture.definition),
                    ZfcAxiom::Pairing,
                    0,
                );
                assert!(matches!(
                    driver
                        .commit_finality_envelope(
                            local.canonical_envelope_bytes(),
                            local.canonical_artifact_bytes().to_vec()
                        )
                        .unwrap(),
                    FixedValidatorNodeDriverEnvelopeOutcomeV0::Finality { .. }
                ));
            })
            .unwrap();
    }
}
