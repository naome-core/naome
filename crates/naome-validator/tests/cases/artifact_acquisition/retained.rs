use super::*;
use naome_consensus::{
    ConsensusRound, ConsensusVoteRole, ConsensusVoteTarget, FixedConsensusBranchV0,
    VerifiedConsensusVoteV0,
};
use naome_network::ConsensusPushMessage;
use naome_storage::{
    FixedValidatorAnchoredFinalityJournalV0, FixedValidatorAnchoredVoteSafetyJournalV0,
    FixedValidatorFinalityReplayLimitV0, FixedValidatorSignerRecoveryRoundLimitV0,
    FixedValidatorVoteSafetyReplayLimitV0,
};

#[test]
fn stored_retained_authoring_uses_real_round_zero_certificate_across_round_and_restart() {
    let fixture = history::dominant_fixture();
    let layout = Layout::new();
    let provider = Plan::new(fixture.peers[0]);
    let peer = provider.peer;
    let config = source_config(
        &layout,
        provider.configure(fixture.config(&layout, 0, "create", None, false)),
    )
    .replace(
        "publication_targets = []",
        &format!("publication_targets = [{:?}]", peer.to_string()),
    )
    .replace(
        "[limits.finality]\nentries = \"8\"",
        "[limits.finality]\nentries = \"1\"",
    )
    .replace(
        "[timeouts.precommit]\nbase_millis = \"60000\"",
        "[timeouts.precommit]\nbase_millis = \"3000\"",
    );
    let mut node = Process::start(&layout, &config);
    node.ready();
    let node_address = address(&mut node);
    let (blocks, payloads) = branch(&fixture, 1);
    let target = hex(blocks[0].id().as_bytes());
    let provider_guard = PARENT_JOURNALS.read().unwrap();
    let sdk = provider.start(
        &provider_guard,
        fixture.definition,
        &node_address,
        blocks.clone(),
        payloads.clone(),
        None,
    );
    connected(&mut node, peer);
    acquire(
        &mut node,
        json!({"command":"acquire_ancestry", "id":1, "target":target, "peer_id":peer.to_string()}),
    );
    sdk.request("block", &target);
    acquire(
        &mut node,
        json!({"command":"acquire_payloads", "id":2, "target":target, "peer_id":peer.to_string(), "max_blocks":1}),
    );
    sdk.request("payload", &hex(blocks[0].artifact_id().as_bytes()));
    let sources = source_images(&layout);
    assert_eq!(
        result(
            &mut node,
            json!({"command":"author_candidate", "id":3, "target":target})
        )["event"],
        "proposal_authored"
    );
    for _ in 0..3 {
        node.event("publication_complete");
    }
    assert_eq!(
        result(
            &mut node,
            json!({"command":"discard_inbox", "id":4, "inbox":"finality"})
        )["discarded_items"],
        1
    );
    let ConsensusPushMessage::Proposal {
        canonical_proposal,
        canonical_artifact,
    } = sdk.message()
    else {
        panic!("actual R0 proposal")
    };
    let ConsensusPushMessage::Vote {
        canonical_vote: prevote,
    } = sdk.message()
    else {
        panic!("actual R0 prevote")
    };
    let ConsensusPushMessage::Vote {
        canonical_vote: precommit,
    } = sdk.message()
    else {
        panic!("actual R0 precommit")
    };
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        fixture.context,
        &fixture.entries,
        ArtifactChainState::new(fixture.definition).branch_snapshot(),
    )
    .unwrap();
    let round_zero = branch.begin_round_zero().unwrap();
    let original = round_zero
        .decode_and_verify_proposal_control(&canonical_proposal, canonical_artifact)
        .unwrap();
    let root = original.proposal_signing_root();
    let target = ConsensusVoteTarget::Proposal(root);
    let signed = VerifiedConsensusVoteV0::decode_and_verify(&precommit, fixture.context).unwrap();
    assert_eq!(signed.signer(), fixture.entries[0].consensus_key());
    assert_eq!(signed.role(), ConsensusVoteRole::Precommit);
    assert_eq!(signed.target(), target);
    let certificate = round_zero
        .build_quorum_certificate_from_signed_votes(&[&prevote], ConsensusVoteRole::Prevote, target)
        .unwrap()
        .to_canonical_bytes();
    sdk.hold_consensus();
    // A real deadline may have fired while the discard command was waiting
    // for its reply. Preserve that ordered observation rather than waiting
    // for a second occurrence of the same round transition.
    let transitioned = |v: &Value| {
        v["event"] == "transitioned"
            && v["height"] == "1"
            && v["round"] == "1"
            && v["phase"] == "Proposal"
    };
    if !node.observed.iter().any(transitioned) {
        node.until(transitioned);
    }
    let transition_index = node.observed.iter().position(transitioned).unwrap();
    let armed = |v: &Value| v["event"] == "timer_armed" && v["phase"] == "Proposal";
    if !node.observed[transition_index + 1..].iter().any(armed) {
        node.until(armed);
    }
    assert_eq!(
        result(
            &mut node,
            json!({"command":"author_stored_retained", "id":5})
        )["event"],
        "proposal_authored"
    );
    let ConsensusPushMessage::Proposal {
        canonical_proposal,
        canonical_artifact,
    } = sdk.message()
    else {
        panic!("actual retained R1 proposal")
    };
    let round_one = round_zero.advance_round().unwrap();
    assert_eq!(round_one.proposer(), fixture.entries[0].consensus_key());
    let retained = round_one
        .decode_and_verify_proposal_control(&canonical_proposal, canonical_artifact)
        .unwrap();
    assert_eq!(retained.proposal_signing_root(), root);
    assert_eq!(retained.value().artifact_block(), blocks[0]);
    assert_eq!(
        retained.valid_round_certificate_bytes(),
        Some(certificate.as_slice())
    );
    assert_eq!(source_images(&layout), sources);
    assert!(!node.observed.iter().any(|v| v["event"] == "finality"));
    // The held receipt keeps R1 publication custody and prevents a later R1
    // prevote from replacing the exact R0 valid certificate before shutdown.
    let stopped = node.shutdown();
    assert_eq!(
        stopped["discarded"]["publication"]["deliveries"][0]["state"],
        "in_flight"
    );
    sdk.stop();
    drop(provider_guard);
    let authority = layout.images();
    {
        let _guard = PARENT_JOURNALS.read().unwrap();
        let finality = FixedValidatorAnchoredFinalityJournalV0::open(
            layout.root.join("finality-journal"),
            layout.root.join("finality-anchor"),
            fixture.definition,
            fixture.context,
            &fixture.entries,
            FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
        )
        .unwrap();
        assert_eq!(finality.finalized_len().unwrap(), 0);
        let mut votes = FixedValidatorAnchoredVoteSafetyJournalV0::open(
            layout.root.join("vote-journal"),
            layout.root.join("vote-anchor"),
            fixture.context,
            finality.fixed_agreement_set_id(),
            fixture.keys[0].clone(),
            FixedValidatorVoteSafetyReplayLimitV0::new(32).unwrap(),
        )
        .unwrap();
        let recovered_branch = finality
            .recover_anchored_signer_branch(votes.acknowledge_signer_recovery().unwrap())
            .unwrap();
        let recovered = votes
            .issue_recovered_signing_session(
                recovered_branch,
                FixedValidatorSignerRecoveryRoundLimitV0::new(4),
            )
            .unwrap();
        let session = recovered.session();
        assert_eq!(
            session.locked_value().unwrap().round(),
            ConsensusRound::new(0)
        );
        assert_eq!(
            session
                .locked_value()
                .unwrap()
                .value()
                .proposal_signing_root(),
            root
        );
        let valid = session.valid_value().unwrap();
        assert_eq!(valid.round(), ConsensusRound::new(0));
        assert_eq!(valid.value().proposal_signing_root(), root);
        assert_eq!(valid.canonical_prevote_certificate(), certificate);
    }
    assert_eq!(layout.images(), authority);
    let mut reopened = Process::start(
        &layout,
        &config.replace("mode = \"create\"", "mode = \"open\""),
    );
    let status = reopened.ready();
    assert_eq!(status["driver"]["height"], "1");
    assert_eq!(status["driver"]["round"], "1");
    assert!(
        result(&mut reopened, json!({"command":"sources_status", "id":6}))["acquisition"].is_null()
    );
    reopened.shutdown();
    assert_eq!(source_images(&layout), sources);
    assert_eq!(layout.images(), authority);
}
