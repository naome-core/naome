use super::*;
use naome_consensus::{
    ConsensusRound, ConsensusValueV0, ConsensusVoteRole, ConsensusVoteTarget,
    FixedValidatorLockPhaseV0, FixedValidatorProposalSourceV0,
};
use naome_network::{ConsensusPushMessage, StaticArtifactNetwork};
use naome_node::{
    FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0,
    FixedValidatorNodeCurrentRoundInboxLimitsV0,
    FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0,
    FixedValidatorNodeDriverAdmissionOutcomeV0 as Admission,
    FixedValidatorNodeDriverCommandV0 as Command, FixedValidatorNodeDriverEventV0 as Input,
    FixedValidatorNodeDriverStepOutcomeV0 as Step, FixedValidatorNodeDriverV0 as Driver,
    FixedValidatorNodeHigherRoundInboxLimitsV0,
};
use naome_runtime::{
    FixedValidatorPhaseDurationV0, FixedValidatorRuntimeEventV0 as Event,
    FixedValidatorRuntimeTimeoutsV0, FixedValidatorRuntimeV0 as Runtime,
};

pub struct Proof {
    pub value: ConsensusValueV0,
    pub control: Vec<u8>,
    pub payload: Vec<u8>,
    pub vote: Vec<u8>,
    pub certificate: Vec<u8>,
    pub envelope: Option<Vec<u8>>,
    pub round: u64,
    pub role: ConsensusVoteRole,
}

impl Proof {
    /// Every proposal and vote comes from a real anchored signer in a separate
    /// throwaway layout. Conflicting fixtures do not bypass one journal's guard.
    pub fn new(fixture: &Fixture, higher: bool, axiom: u8, role: ConsensusVoteRole) -> Self {
        Self::after_prefix(fixture, &[], u64::from(higher), axiom, role)
    }

    pub fn after_prefix(
        fixture: &Fixture,
        prefix: &[&Proof],
        minimum_round: u64,
        axiom: u8,
        role: ConsensusVoteRole,
    ) -> Self {
        let _guard = PARENT_JOURNALS.read().unwrap();
        let layout = Layout::new();
        let mut selected = ArtifactChainState::new(fixture.definition);
        let mut branch = FixedConsensusBranchV0::try_from_virtual_genesis(
            fixture.context,
            &fixture.entries,
            selected.branch_snapshot(),
        )
        .unwrap();
        for proof in prefix {
            let transition = branch
                .decode_and_verify_envelope_with_round_limit(
                    proof.envelope.as_ref().unwrap(),
                    proof.payload.clone(),
                    ConsensusRound::new(4),
                )
                .unwrap();
            selected
                .apply_block(&transition.value().artifact_block(), proof.payload.clone())
                .unwrap();
            branch = transition.into_branch();
        }
        let mut round = branch.begin_round_zero().unwrap();
        while round.position().round().value() < minimum_round
            || round.proposer() != key(&fixture.keys[0])
        {
            round = round.advance_round().unwrap();
        }
        assert!(round.position().round().value() <= 4);
        let payload = ArtifactPayload::Proof(
            ProofCertificate::from_canonical_bytes(&[0, 0, 0, 1, 0x10, axiom]).unwrap(),
        )
        .to_canonical_bytes();
        let artifact = ArtifactDag::new()
            .apply_canonical_artifact_bytes(payload.clone())
            .unwrap()
            .artifact_id();
        let block = selected.prepare_block(artifact).unwrap();
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (control, vote) = fixture.create_node(&layout).run_with_signing_session(|mut scope| {
            for proof in prefix {
                let transition = scope.branch().decode_and_verify_envelope_with_round_limit(proof.envelope.as_ref().unwrap(), proof.payload.clone(), ConsensusRound::new(4)).unwrap();
                let naome_node::FixedValidatorNodeFinalityOutcomeV0::Continues { scope: next, .. } = scope.commit_verified_finality(transition).unwrap() else { panic!("fixture selected prefix") };
                scope = *next;
            }
            let mut driver = arm(Driver::new(
                scope,
                FixedValidatorNodeHigherRoundInboxLimitsV0::new(8, 1_048_576).unwrap(),
                FixedValidatorNodeCurrentRoundInboxLimitsV0::new(8, 1_048_576).unwrap(),
                FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0::new(8, 1_048_576).unwrap(),
                FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0::new(8, 1_048_576).unwrap(),
                ConsensusRound::new(4),
            ).unwrap());
            while driver.position().round() != round.position().round() {
                driver = empty_round(driver);
            }
            executor.block_on(async {
                let phase = FixedValidatorPhaseDurationV0::new(Duration::from_secs(60), Duration::from_millis(1)).unwrap();
                let mut runtime = Runtime::new(driver, StaticArtifactNetwork::new(Keypair::generate_ed25519(), []).unwrap(), vec![], FixedValidatorRuntimeTimeoutsV0::new(phase, phase, phase)).unwrap();
                assert!(matches!(runtime.next_event().await, Event::TimerArmed(_)));
                assert!(matches!(runtime.author_proposal(FixedValidatorProposalSourceV0::Fresh {
                    artifact_block: block, canonical_artifact_bytes: payload.clone(),
                }), Event::ProposalAuthored));
                let mut proposal = None;
                for _ in 0..32 {
                    match runtime.next_event().await {
                        Event::PublicationComplete(publication) => match publication.message().copy_message().unwrap() {
                            ConsensusPushMessage::Proposal { canonical_proposal, .. } => proposal = Some(canonical_proposal),
                            ConsensusPushMessage::Vote { canonical_vote } => {
                                let observed = naome_consensus::UnverifiedConsensusVoteRouteV0::inspect(&canonical_vote).unwrap();
                                if observed.role() == role { return (proposal.unwrap(), canonical_vote); }
                            }
                        },
                        Event::Admission(report) => assert!(report.all_admitted()),
                        Event::PublicationPrepared(_) | Event::TimerArmed(_) | Event::Transitioned { .. } => {},
                        _ => panic!("unexpected fixture event"),
                    }
                }
                panic!("fixture did not publish exact vote")
            })
        }).unwrap();
        let admitted = round
            .decode_and_verify_proposal_control(&control, payload.clone())
            .unwrap();
        let certificate = round
            .build_quorum_certificate_from_signed_votes(
                &[&vote],
                role,
                ConsensusVoteTarget::Proposal(admitted.proposal_signing_root()),
            )
            .unwrap()
            .to_canonical_bytes();
        let value = admitted.value();
        let envelope = if role == ConsensusVoteRole::Precommit {
            Some(
                admitted
                    .seal_with_precommit_vote_batch(&[&vote])
                    .unwrap()
                    .into_owned()
                    .canonical_envelope_bytes()
                    .to_vec(),
            )
        } else {
            None
        };
        Self {
            value,
            control,
            payload,
            vote,
            certificate,
            envelope,
            round: round.position().round().value(),
            role,
        }
    }

    pub fn write(&self, layout: &Layout, prefix: &str) {
        layout.write(&format!("{prefix}.control"), &self.control);
        layout.write(&format!("{prefix}.payload"), &self.payload);
        layout.write(&format!("{prefix}.vote"), &self.vote);
        layout.write(&format!("{prefix}.certificate"), &self.certificate);
        if let Some(envelope) = &self.envelope {
            layout.write(&format!("{prefix}.envelope"), envelope);
        }
    }
    pub fn files(prefix: &str) -> Value {
        json!({"control_file": format!("{prefix}.control"), "payload_file": format!("{prefix}.payload"), "vote_files": [format!("{prefix}.vote")]})
    }
    pub fn higher_command(&self, id: u64, prefix: &str, batch: bool) -> Value {
        if batch {
            json!({"command": "advance_higher_votes", "id": id, "evidence_round": self.round,
                "role": match self.role { ConsensusVoteRole::Prevote => "prevote", ConsensusVoteRole::Precommit => "precommit" },
                "target": {"kind": "proposal", "root": hex(self.value.proposal_signing_root().as_bytes())}, "vote_files": [format!("{prefix}.vote")]})
        } else {
            json!({"command": "advance_higher_quorum", "id": id, "certificate_file": format!("{prefix}.certificate")})
        }
    }
    pub fn current_command(&self, id: u64, prefix: &str, batch: bool) -> Value {
        if batch {
            json!({"command": "finalize_current_votes", "id": id, "proof": Self::files(prefix)})
        } else {
            json!({"command": "finalize_current_quorum", "id": id, "control_file": format!("{prefix}.control"), "payload_file": format!("{prefix}.payload"), "certificate_file": format!("{prefix}.certificate")})
        }
    }

    pub fn lower_command(&self, id: u64, prefix: &str, batch: bool) -> Value {
        if batch {
            json!({"command": "finalize_lower_votes", "id": id, "evidence_round": self.round, "proof": Self::files(prefix)})
        } else {
            json!({"command": "finalize_lower_quorum", "id": id, "control_file": format!("{prefix}.control"), "payload_file": format!("{prefix}.payload"), "certificate_file": format!("{prefix}.certificate")})
        }
    }
}

fn arm(driver: Driver<'_>) -> Driver<'_> {
    match driver.step().unwrap() {
        Step::Command {
            driver,
            command: Command::ArmPhaseTimeout(_),
        } => *driver,
        _ => panic!("fixture arm missing"),
    }
}

fn empty_round(mut driver: Driver<'_>) -> Driver<'_> {
    for _ in 0..3 {
        let ticket = driver.active_timeout().unwrap();
        driver = match driver.admit_event(Input::TimeoutDue(ticket)).unwrap() {
            Admission::Admitted { driver, .. } => *driver,
            _ => panic!("fixture timeout admission"),
        };
        driver = match driver.step().unwrap() {
            Step::Transitioned { driver } => *driver,
            _ => panic!("fixture transition"),
        };
        if driver.phase() != FixedValidatorLockPhaseV0::Proposal {
            driver = match driver.step().unwrap() {
                Step::Command {
                    driver,
                    command:
                        Command::PublishVote {
                            vote,
                            released_proposal: None,
                        },
                } => {
                    assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
                    *driver
                }
                _ => panic!("fixture nil vote"),
            };
        }
        driver = arm(driver);
    }
    driver
}
