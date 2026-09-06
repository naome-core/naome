use super::*;

#[test]
fn active_acquisition_refuses_candidate_proofs_until_cancel_and_direct_historical_proofs_still_halt()
 {
    let fixture = Fixture::new();
    let first = Proof::new(&fixture, false, 1, Role::Precommit);
    let sibling = Proof::new(&fixture, false, 2, Role::Precommit);
    let (blocks, payloads) = branch(&fixture, 2);
    assert_eq!(blocks[0], first.value.artifact_block());
    for action in ["cancel", "envelope", "votes"] {
        let layout = Layout::new();
        sibling.write(&layout, "sibling");
        let plan = Plan::new(fixture.peers[1]);
        let peer = plan.peer;
        let config = source_config(
            &layout,
            plan.configure(fixture.config(&layout, 1, "create", None, false)),
        );
        let mut node = Process::start(&layout, &config);
        node.ready();
        let address = address(&mut node);
        initial_arm(&mut node);
        let target = hex(blocks[1].id().as_bytes());
        let provider_guard = PARENT_JOURNALS.read().unwrap();
        let sdk = plan.start(
            &provider_guard,
            fixture.definition,
            &address,
            vec![blocks[0], blocks[1], sibling.value.artifact_block()],
            payloads.clone(),
            Some(target.clone()),
        );
        connected(&mut node, peer);
        load(&mut node, &sdk, peer, &sibling);
        select(&mut node, &layout, &[&first]);
        assert_eq!(
            result(
                &mut node,
                json!({"command":"acquire_ancestry", "id":30, "target":target, "peer_id":peer.to_string()})
            )["event"],
            "acquisition_started"
        );
        sdk.request("block", &target);
        let authority = layout.images();
        let sources = source_images(&layout);
        let active = result(&mut node, json!({"command":"sources_status", "id":31}));
        for conflict in [false, true] {
            let mut input = command(&sibling, "missing", conflict);
            input["target"] = json!("invalid");
            input["vote_files"] = json!([]);
            node.send(input);
            assert_eq!(node.event("command_rejected")["code"], "sources_busy");
        }
        assert_eq!(
            result(&mut node, json!({"command":"sources_status", "id":32})),
            active
        );
        assert_eq!(layout.images(), authority);
        assert_eq!(source_images(&layout), sources);
        let input = match action {
            "cancel" => {
                assert_eq!(
                    result(&mut node, json!({"command":"cancel_acquisition", "id":33}))["active"],
                    true
                );
                assert!(
                    result(&mut node, json!({"command":"sources_status", "id":34}))["acquisition"]
                        .is_null()
                );
                command(&sibling, "sibling", true)
            }
            "envelope" => {
                json!({"command":"halt_historical_envelope", "id":35, "envelope_file":"sibling.envelope", "payload_file":"sibling.payload"})
            }
            "votes" => {
                json!({"command":"halt_historical_votes", "id":35, "evidence_round":sibling.round, "proof":Proof::files("sibling")})
            }
            _ => unreachable!(),
        };
        halt(&result(&mut node, input), &first, &sibling);
        if action != "cancel" {
            let cancelled = node.event("acquisition_cancelled");
            assert_eq!(cancelled["id"], 30);
            assert_eq!(cancelled["reason"], "command_fatal");
        }
        stopped(&mut node);
        assert_eq!(source_images(&layout), sources);
        assert!(
            !node
                .observed
                .iter()
                .any(|v| v["event"] == "acquisition_complete" && v["id"] == 30)
        );
        sdk.stop();
        drop(provider_guard);
        let durable = layout.images();
        let mut reopened = Process::start(&layout, &config.replace("create", "open"));
        assert_eq!(reopened.event("error")["code"], "startup_finality_stopped");
        assert!(!reopened.exit().success());
        assert_eq!(layout.images(), durable);
        assert_eq!(source_images(&layout), sources);
    }
}

#[test]
fn candidate_proofs_preserve_positive_busy_and_consuming_historical_custody_during_real_publication()
 {
    let fixture = Fixture::new();
    let first = Proof::new(&fixture, false, 1, Role::Precommit);
    let second = Proof::after_prefix(&fixture, &[&first], 0, 3, Role::Precommit);
    let sibling = Proof::after_prefix(&fixture, &[], 2, 2, Role::Precommit);
    let higher = Proof::after_prefix(&fixture, &[&first, &second], 1, 2, Role::Prevote);
    for valid in [false, true] {
        let layout = Layout::new();
        write_proof(&sibling, &layout, "sibling");
        higher.write(&layout, "higher");
        let plan = Plan::new(fixture.peers[1]);
        let peer = plan.peer;
        let config = source_config(
            &layout,
            plan.configure(fixture.config(&layout, 1, "create", None, false))
                .replace(
                    "publication_targets = []",
                    &format!("publication_targets = [{:?}]", peer.to_string()),
                ),
        );
        let mut node = Process::start(&layout, &config);
        node.ready();
        let address = address(&mut node);
        initial_arm(&mut node);
        let provider_guard = PARENT_JOURNALS.read().unwrap();
        let sdk = plan.start(
            &provider_guard,
            fixture.definition,
            &address,
            vec![sibling.value.artifact_block()],
            vec![sibling.payload.clone()],
            None,
        );
        connected(&mut node, peer);
        load(&mut node, &sdk, peer, &sibling);
        select(&mut node, &layout, &[&first, &second]);
        sdk.hold_consensus();
        result(
            &mut node,
            json!({"command":"submit_proposal", "id":1, "control_file":"higher.control", "payload_file":"higher.payload"}),
        );
        assert_eq!(node.event("admission")["all_admitted"], true);
        result(
            &mut node,
            json!({"command":"submit_vote", "id":2, "vote_file":"higher.vote"}),
        );
        assert_eq!(node.event("admission")["all_admitted"], true);
        let transition = node.event("transitioned");
        assert_eq!(transition["height"], "3");
        assert_eq!(transition["round"], higher.round.to_string());
        assert_eq!(transition["phase"], "Precommit");
        assert_eq!(node.event("peer_attempted")["started"], true);
        let naome_network::ConsensusPushMessage::Vote { canonical_vote } = sdk.message() else {
            panic!("actual process precommit")
        };
        let route =
            naome_consensus::UnverifiedConsensusVoteRouteV0::inspect(&canonical_vote).unwrap();
        assert_eq!(route.role(), Role::Precommit);
        let initial = result(&mut node, json!({"command":"status", "id":3}));
        assert_eq!(initial["publication"]["released_proposal"], true);
        assert_eq!(
            initial["publication"]["deliveries"][0]["state"],
            "in_flight"
        );
        let sources = source_images(&layout);
        let authority = layout.images();
        let busy = result(&mut node, command(&sibling, "sibling", false));
        assert_eq!(busy["event"], "proof_refused");
        assert_eq!(busy["reason"], "busy");
        assert_eq!(busy["refunded_payloads_discarded"], 0);
        assert_eq!(busy["state"], initial);
        assert_eq!(layout.images(), authority);
        assert_eq!(source_images(&layout), sources);
        let mut input = command(&sibling, "sibling", true);
        if !valid {
            input["vote_files"] = json!(["sibling.vote", "sibling.vote"]);
        }
        let outcome = result(&mut node, input);
        if valid {
            halt(&outcome, &first, &sibling);
        } else {
            failed(&outcome, true);
            assert_eq!(layout.images(), authority);
        }
        assert_eq!(outcome["state"]["publication"], initial["publication"]);
        assert_eq!(outcome["state"]["timer"], initial["timer"]);
        let stop = stopped(&mut node);
        assert_eq!(stop["discarded"]["publication"], initial["publication"]);
        assert!(stop["discarded"]["driver"].is_null());
        assert_eq!(source_images(&layout), sources);
        assert!(!node.observed.iter().any(|v| v["event"] == "peer_completed"));
        sdk.stop();
        drop(provider_guard);
        let durable = layout.images();
        let mut reopened = Process::start(&layout, &config.replace("create", "open"));
        if valid {
            assert_eq!(reopened.event("error")["code"], "startup_finality_stopped");
            assert!(!reopened.exit().success());
        } else {
            let ready = reopened.ready();
            for field in ["height", "round", "phase", "head"] {
                assert_eq!(ready["driver"][field], initial["driver"][field]);
            }
            reopened.shutdown();
        }
        assert_eq!(layout.images(), durable);
        assert_eq!(source_images(&layout), sources);
    }
}
