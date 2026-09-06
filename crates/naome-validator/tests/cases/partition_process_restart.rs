use super::*;
use naome_consensus::{
    ConsensusPosition, ConsensusRound, ConsensusVoteRole, ConsensusVoteTarget,
    FixedValidatorLockPhaseV0, FixedValidatorValidValueV0, VerifiedConsensusVoteV0,
    VerifiedQuorumCertificateV0,
};
use naome_storage::{
    FixedValidatorAnchoredVoteSafetyJournalV0, FixedValidatorProposalReplayLimitV0,
    FixedValidatorSignerRecoveryRoundLimitV0, FixedValidatorVoteSafetyReplayLimitV0,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    os::unix::process::ExitStatusExt,
};

// The outer array indexes actual immutable consensus keys. Position and role
// index completed signatures, never transport peer labels or publication counts.
type CompletedVotes = BTreeMap<(u64, u64, u8), Vec<u8>>;

struct Recovered {
    branch: FixedConsensusBranchV0,
    votes: CompletedVotes,
    valid: Option<FixedValidatorValidValueV0>,
}

fn inspect(corpus: &Corpus, layout: &Layout, actor: usize, round: Option<u64>) -> Recovered {
    let before = layout.images();
    let recovered = {
        let _guard = PARENT_JOURNALS.read().unwrap();
        let finality = FixedValidatorAnchoredFinalityJournalV0::open(
            layout.root.join("finality-journal"),
            layout.root.join("finality-anchor"),
            corpus.definition,
            corpus.context,
            &corpus.entries,
            FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
        )
        .unwrap();
        assert!(finality.halt().unwrap().is_none());
        assert_eq!(finality.finalized_len().unwrap(), 1);
        assert_eq!(
            finality.artifact_head_block_id().unwrap(),
            corpus.blocks[0].id()
        );
        let mut journal = FixedValidatorAnchoredVoteSafetyJournalV0::open(
            layout.root.join("vote-journal"),
            layout.root.join("vote-anchor"),
            corpus.context,
            finality.fixed_agreement_set_id(),
            corpus.keys[actor].clone(),
            FixedValidatorVoteSafetyReplayLimitV0::new(64).unwrap(),
        )
        .unwrap();
        assert!(journal.halt().unwrap().is_none());
        assert!(journal.proposal_halt().unwrap().is_none());
        assert!(journal.finality_conflict_stop().unwrap().is_none());
        assert!(journal.pending_vote().unwrap().is_none());
        assert!(journal.pending_proposal().unwrap().is_none());
        assert_eq!(
            journal.proposal_replay_limit(),
            Some(FixedValidatorProposalReplayLimitV0::new(8).unwrap())
        );
        let mut votes = BTreeMap::new();
        for height in 1..=2 {
            for round in 0..=4 {
                let position = ConsensusPosition::new(
                    ConsensusHeight::new(height),
                    ConsensusRound::new(round),
                );
                for (role_id, role) in [ConsensusVoteRole::Prevote, ConsensusVoteRole::Precommit]
                    .into_iter()
                    .enumerate()
                {
                    if let Some(vote) = journal.retained_signed_vote(position, role).unwrap() {
                        let verified = VerifiedConsensusVoteV0::decode_and_verify(
                            vote.canonical_bytes(),
                            corpus.context,
                        )
                        .unwrap();
                        assert_eq!(verified.signer(), corpus.entries[actor].consensus_key());
                        assert_eq!(verified.position(), position);
                        assert_eq!(verified.role(), role);
                        assert_eq!(verified.target(), vote.target());
                        votes.insert(
                            (height, round, role_id as u8),
                            vote.canonical_bytes().to_vec(),
                        );
                    }
                }
            }
        }
        let branch = finality
            .recover_anchored_signer_branch(journal.acknowledge_signer_recovery().unwrap())
            .unwrap();
        let recovered = journal
            .issue_recovered_signing_session(
                branch,
                FixedValidatorSignerRecoveryRoundLimitV0::new(4),
            )
            .unwrap();
        let session = recovered.session();
        assert_eq!(session.position().height().value(), 2);
        if let Some(round) = round {
            assert_eq!(session.position().round().value(), round);
            assert_eq!(session.phase(), FixedValidatorLockPhaseV0::Precommit);
            let locked = session
                .locked_value()
                .expect("restart must retain the non-nil lock");
            let valid = session.valid_value().unwrap();
            assert_eq!(locked.round(), ConsensusRound::new(0));
            assert_eq!(valid.round(), ConsensusRound::new(0));
            assert_eq!(locked.value(), valid.value());
            assert_eq!(valid.value().artifact_block(), corpus.blocks[1]);
            assert_eq!(
                valid.value().parent_ancestry_id(),
                finality
                    .finality_record(ConsensusHeight::new(1))
                    .unwrap()
                    .unwrap()
                    .value()
                    .ancestry_id()
            );
        } else {
            assert!(
                session.locked_value().is_none(),
                "a leaf never receives quorum prevotes"
            );
            assert!(session.valid_value().is_none());
        }
        Recovered {
            branch: recovered.branch().clone(),
            votes,
            valid: session.valid_value().cloned(),
        }
    };
    assert_eq!(
        layout.images(),
        before,
        "strict diagnostics must not repair or advance authority"
    );
    recovered
}

fn transitioned(node: &Process, round: &str, phase: &str) -> bool {
    node.observed.iter().any(|event| {
        event["event"] == "transitioned"
            && event["height"] == "2"
            && event["round"] == round
            && event["phase"] == phase
    })
}

fn no_finality(layouts: &[Layout; 4], baseline: &[Images; 4]) {
    for actor in 0..4 {
        assert_eq!(finality_images(&layouts[actor]), baseline[actor]);
    }
}

fn target(corpus: &Corpus, bytes: &[u8]) -> ConsensusVoteTarget {
    VerifiedConsensusVoteV0::decode_and_verify(bytes, corpus.context)
        .unwrap()
        .target()
}

#[test]
fn actual_process_kill_under_partition_preserves_lock_and_continues_voting() {
    let corpus = Corpus::new([1; 4]);
    let center = corpus.proposers[1];
    let total: u128 = corpus
        .entries
        .iter()
        .map(|entry| entry.agreement_weight().units())
        .sum();
    assert_eq!(total, 4);
    for actor in (0..4).filter(|&actor| actor != center) {
        let available = corpus.entries[actor].agreement_weight().units()
            + corpus.entries[center].agreement_weight().units();
        assert!(3 * available <= 2 * total);
    }
    let layouts = std::array::from_fn(|_| Layout::new());
    let mut gates = std::array::from_fn(|_| Gate::bind());
    // Leave ample time for the exact crash checkpoint; this is an explicit
    // fixture profile, not paused time or a persisted timer guarantee.
    let (mut nodes, baseline) = start_on_h1(&corpus, &layouts, &mut gates, 60_000);
    let original_pids = nodes.each_ref().map(|node| node.child.id());
    let star_start = nodes.each_ref().map(|node| node.observed.len());
    for (gate, &(a, b)) in gates.iter().zip(&PAIRS) {
        if a != center && b != center {
            gate.cut();
        }
    }
    pump_until(&mut nodes, "leaf paths disconnected before H2", |nodes| {
        no_finality(&layouts, &baseline);
        (0..4).filter(|&actor| actor != center).all(|actor| {
            (0..4)
                .filter(|&other| other != center && other != actor)
                .all(|other| {
                    nodes[actor].observed[star_start[actor]..]
                        .iter()
                        .any(|event| {
                            event["event"] == "peer_session"
                                && event["state"] == "disconnected"
                                && event["peer"] == corpus.peers[other].to_string()
                        })
                })
        })
    });
    let proposal_start = nodes.each_ref().map(|node| node.observed.len());
    corpus.author(&mut nodes, &layouts, 1);
    pump_until(
        &mut nodes,
        "center non-nil precommit completed through the star",
        |nodes| {
            no_finality(&layouts, &baseline);
            let node = &nodes[center];
            transitioned(node, "0", "Precommit")
                && node.observed[proposal_start[center]..].iter().any(|event| {
                    admitted(event, "CurrentProposalPrecommit")
                        && event["source"]["kind"] == "local_publication"
                })
                && node
                    .observed
                    .iter()
                    .filter(|event| event["event"] == "publication_prepared")
                    .count()
                    == node
                        .observed
                        .iter()
                        .filter(|event| event["event"] == "publication_complete")
                        .count()
        },
    );
    // With only center/leaf paths, the center can receive 3/4 prevotes. Each
    // leaf has at most 2/4 and cannot produce a non-nil precommit. The center's
    // one non-nil precommit cannot finalize anywhere, even if fully delivered.
    let before_transition = nodes[center].observed[proposal_start[center]..]
        .iter()
        .position(|event| event["event"] == "transitioned" && event["phase"] == "Precommit")
        .unwrap();
    let mut admitted_keys = BTreeSet::new();
    for event in
        &nodes[center].observed[proposal_start[center]..proposal_start[center] + before_transition]
    {
        if admitted(event, "CurrentProposalPrevote") {
            let actor = if event["source"]["kind"] == "local_publication" {
                center
            } else {
                assert_eq!(event["source"]["kind"], "peer");
                assert_eq!(event["receipt_queued"], true);
                corpus
                    .peers
                    .iter()
                    .position(|peer| event["source"]["peer"] == peer.to_string())
                    .unwrap()
            };
            admitted_keys.insert(corpus.entries[actor].consensus_key());
        }
    }
    assert!(3 * admitted_keys.len() > 2 * 4);
    for gate in &gates {
        gate.cut();
    }
    nodes[center].child.kill().unwrap();
    let killed = nodes[center].exit();
    assert_eq!(
        killed.signal(),
        Some(rustix::process::Signal::KILL.as_raw()),
        "the original signer must exit from SIGKILL, not an intervening error shutdown: {killed}"
    );
    let killed_transcript = nodes[center].observed.clone();
    assert!(
        !killed_transcript
            .iter()
            .any(|event| event["event"] == "stopped")
    );
    for actor in (0..4).filter(|&actor| actor != center) {
        assert!(nodes[actor].child.try_wait().unwrap().is_none());
        assert_eq!(nodes[actor].child.id(), original_pids[actor]);
    }
    let crash_images = layouts[center].images();
    let crash = inspect(&corpus, &layouts[center], center, Some(0));
    let valid = crash.valid.as_ref().unwrap();
    let locked_target = ConsensusVoteTarget::Proposal(valid.value().proposal_signing_root());
    for role in 0..=1 {
        assert_eq!(target(&corpus, &crash.votes[&(2, 0, role)]), locked_target);
    }
    assert!(
        crash
            .votes
            .keys()
            .all(|&(height, round, _)| height != 2 || round == 0)
    );
    assert_eq!(layouts[center].images(), crash_images);
    no_finality(&layouts, &baseline);

    // No original proposal source or peer proof is supplied to the new process.
    fs::remove_file(layouts[center].root.join("block.bin")).unwrap();
    fs::remove_file(layouts[center].root.join("payload.bin")).unwrap();
    let config = corpus
        .config(&layouts[center], center, &gates, 5000)
        .replace("mode = \"create\"", "mode = \"open\"");
    nodes[center] = Process::start(&layouts[center], &config);
    assert_ne!(nodes[center].child.id(), original_pids[center]);
    let ready = nodes[center].ready();
    assert_eq!(ready["driver"]["height"], "2");
    assert_eq!(ready["driver"]["round"], "0");
    assert_eq!(ready["driver"]["phase"], "Precommit");
    assert_eq!(
        ready["driver"]["head"],
        hex(corpus.blocks[0].id().as_bytes())
    );
    for inbox in [
        "higher_inbox",
        "current_inbox",
        "finality_inbox",
        "nil_precommit_inbox",
    ] {
        assert_eq!(ready["driver"][inbox], 0);
    }
    // Fresh driver construction queues its initial timeout-arm command.
    assert_eq!(ready["driver"]["pending_command"], true);
    assert_eq!(ready["driver"]["timeout_due"], false);
    assert_eq!(ready["timer"], false);
    assert!(ready["publication"].is_null());
    assert_eq!(layouts[center].images(), crash_images);
    pump_until(
        &mut nodes,
        "restarted locked owner reaches R2 through real deadlines",
        |nodes| {
            no_finality(&layouts, &baseline);
            transitioned(&nodes[center], "2", "Proposal")
        },
    );
    for actor in (0..4).filter(|&actor| actor != center) {
        assert_eq!(nodes[actor].child.id(), original_pids[actor]);
        assert!(nodes[actor].child.try_wait().unwrap().is_none());
    }
    for actor in std::iter::once(center).chain((0..4).filter(|&actor| actor != center)) {
        let node = &mut nodes[actor];
        assert_eq!(node.shutdown()["locks_released"], true);
        for event in &node.observed {
            healthy(event);
        }
    }
    let restarted = &nodes[center];
    for (round, phase) in [
        ("1", "Proposal"),
        ("1", "Prevote"),
        ("1", "Precommit"),
        ("2", "Proposal"),
    ] {
        assert!(transitioned(restarted, round, phase));
    }
    assert_eq!(
        restarted
            .observed
            .iter()
            .filter(|event| event["event"] == "timer_due" && event["admitted"] == true)
            .count(),
        4
    );
    assert!(
        restarted
            .observed
            .iter()
            .any(|event| admitted(event, "CurrentNilPrecommit")
                && event["source"]["kind"] == "local_publication")
    );
    for event in &restarted.observed {
        assert_ne!(event["event"], "finality");
        if event["event"] == "admission" {
            assert_eq!(event["source"]["kind"], "local_publication");
        }
        if event["event"] == "peer_session" {
            assert_ne!(event["state"], "established");
        }
    }
    for actor in (0..4).filter(|&actor| actor != center) {
        for event in &nodes[actor].observed[proposal_start[actor]..] {
            assert_ne!(event["event"], "finality");
            if event["event"] == "admission" && event["source"]["kind"] == "peer" {
                assert_eq!(event["source"]["peer"], corpus.peers[center].to_string());
            }
        }
    }
    let recovered: [Recovered; 4] = std::array::from_fn(|actor| {
        inspect(
            &corpus,
            &layouts[actor],
            actor,
            (actor == center).then_some(1),
        )
    });
    for actor in 0..4 {
        assert_eq!(
            target(&corpus, &recovered[actor].votes[&(2, 0, 0)]),
            locked_target
        );
        if actor != center {
            if let Some(bytes) = recovered[actor].votes.get(&(2, 0, 1)) {
                assert_eq!(target(&corpus, bytes), ConsensusVoteTarget::Nil);
            }
            let tail = &nodes[actor].observed[proposal_start[actor]..];
            assert!(tail.iter().any(|event| {
                admitted(event, "CurrentVotingProposal")
                    && admitted(event, "CurrentFinalityProposal")
                    && event["source"]["kind"] == "peer"
                    && event["source"]["peer"] == corpus.peers[center].to_string()
                    && event["receipt_queued"] == true
            }));
            assert!(tail.iter().any(|event| {
                admitted(event, "CurrentProposalPrevote")
                    && event["source"]["kind"] == "local_publication"
            }));
        }
    }
    assert_eq!(recovered[center].valid, crash.valid);
    assert_eq!(
        recovered[center].branch.coordinate(),
        crash.branch.coordinate()
    );
    for (slot, bytes) in &crash.votes {
        assert_eq!(
            recovered[center].votes.get(slot),
            Some(bytes),
            "completed signing bytes changed across process generations"
        );
    }
    assert_eq!(recovered[center].votes.len(), crash.votes.len() + 2);
    assert_eq!(
        target(&corpus, &recovered[center].votes[&(2, 1, 0)]),
        locked_target
    );
    assert_eq!(
        target(&corpus, &recovered[center].votes[&(2, 1, 1)]),
        ConsensusVoteTarget::Nil
    );

    let round = crash.branch.begin_round_zero().unwrap();
    let snapshot =
        ActiveAgreementSnapshot::try_from_preselected(round.position(), &corpus.entries).unwrap();
    let certificate = VerifiedQuorumCertificateV0::decode_and_verify(
        valid.canonical_prevote_certificate(),
        corpus.context,
        &snapshot,
    )
    .unwrap();
    assert_eq!(certificate.role(), ConsensusVoteRole::Prevote);
    assert_eq!(certificate.position(), round.position());
    assert_eq!(certificate.target(), locked_target);
    let certificate_votes = certificate
        .signer_keys()
        .map(|key| {
            assert!(
                admitted_keys.contains(&key),
                "certificate includes an unadmitted signer"
            );
            let actor = corpus
                .entries
                .iter()
                .position(|entry| entry.consensus_key() == key)
                .unwrap();
            recovered[actor].votes[&(2, 0, 0)].as_slice()
        })
        .collect::<Vec<_>>();
    assert!(3 * certificate_votes.len() > 2 * 4);
    let rebuilt = round
        .build_quorum_certificate_from_signed_votes(
            &certificate_votes,
            ConsensusVoteRole::Prevote,
            locked_target,
        )
        .unwrap();
    assert_eq!(
        rebuilt.to_canonical_bytes(),
        valid.canonical_prevote_certificate()
    );
    assert_eq!(rebuilt.id(), valid.prevote_certificate_id());
    let histories = layouts.each_ref().map(|layout| corpus.verify(layout, 1));
    assert!(
        histories
            .iter()
            .all(|history| history == &histories[center])
    );
    no_finality(&layouts, &baseline);
    for gate in &mut gates {
        let (accepted, refused) = gate.counts();
        assert_eq!(
            accepted, 1,
            "a blocked path forwarded a replacement connection"
        );
        assert!(refused > 0, "actual redials must reach the blocked gate");
        gate.finish();
    }
}
