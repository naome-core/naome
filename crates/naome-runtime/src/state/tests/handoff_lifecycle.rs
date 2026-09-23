use super::*;
use naome_ledger::time::TimeCertificate;
use naome_network::StateTransportPair;
use naome_storage::state::StateAppendOutcome;

fn free_endpoints() -> Vec<String> {
    let listeners: Vec<_> = (0..8)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let mut endpoints: Vec<_> = listeners
        .iter()
        .map(|listener| listener.local_addr().unwrap().to_string())
        .collect();
    endpoints.sort();
    endpoints
}

fn genesis_at(endpoints: &[String]) -> Genesis {
    genesis_at_with_run_records(endpoints, 70)
}

fn genesis_at_with_run_records(endpoints: &[String], run_records: u64) -> Genesis {
    let base = genesis();
    let mut validators = base.validators().to_vec();
    for validator in &mut validators {
        let index = (0..4)
            .find(|i| {
                SigningKey::from_bytes(&[201 + *i; 32])
                    .verifying_key()
                    .as_bytes()
                    == &validator.transport_key
            })
            .unwrap();
        validator.endpoint = endpoints[index as usize].clone();
    }
    let retirement_order = [2, 0, 3, 1].map(|i| validators[i].id()).to_vec();
    let mut limits = base.profile().limits().clone();
    limits.run_records = run_records;
    Genesis::new(
        Profile::with_limits(TimingKind::ShortTest, limits).unwrap(),
        base.foundation().into(),
        base.checker_profile().into(),
        naome_ledger::profile::STATE_PROTOCOL_VERSION,
        100,
        [9; 32],
        base.accounts().iter().map(|a| *a.key()).collect(),
        validators,
        retirement_order,
    )
    .unwrap()
}

fn reopen_on_recovery(
    directory: Directory,
    anchors: Directory,
    setup: StateHandoffSetup,
    config: StateRuntimeConfig,
    genesis: &Genesis,
) -> Running {
    let history = StateHistory::open(&directory.0, &anchors.0, genesis.clone(), 8).unwrap();
    let selected = history.head().unwrap().state().clone();
    let mut seed = setup.recovery_key.as_ref().unwrap().to_bytes();
    let identity = Keypair::ed25519_from_bytes(&mut seed).unwrap();
    let recovery = StateNetwork::new_recovery_only(identity, &selected).unwrap();
    let runtime = StateRuntime::new_handoff(
        history,
        None,
        StateTransportPair::from_recovery(recovery).unwrap(),
        Vec::new(),
        config,
        setup,
    )
    .unwrap();
    Running {
        directory,
        anchors,
        runtime,
    }
}

fn reopen_selected(
    directory: Directory,
    anchors: Directory,
    setup: StateHandoffSetup,
    config: StateRuntimeConfig,
    genesis: &Genesis,
    consensus_key: SigningKey,
    transport_key: SigningKey,
) -> Running {
    let history = StateHistory::open(&directory.0, &anchors.0, genesis.clone(), 8).unwrap();
    let selected = history.head().unwrap().state().clone();
    let signer =
        StateSigner::open_for_selected(&directory.0, &anchors.0, &history, consensus_key, 8)
            .unwrap();
    let mut seed = transport_key.to_bytes();
    let identity = Keypair::ed25519_from_bytes(&mut seed).unwrap();
    let mut active = StateNetwork::new_for_parent(identity, &selected).unwrap();
    active
        .listen_on(active.state_listen_address().unwrap().clone())
        .unwrap();
    let local = active.local_peer_id();
    let peers = selected
        .authority()
        .units()
        .iter()
        .filter_map(|unit| unit.keys())
        .map(|keys| naome_network::state_peer_id(*keys.transport()).unwrap())
        .filter(|peer| *peer != local)
        .collect();
    let runtime = StateRuntime::new_handoff(
        history,
        Some(signer),
        StateTransportPair::new(active).unwrap(),
        peers,
        config,
        setup,
    )
    .unwrap();
    Running {
        directory,
        anchors,
        runtime,
    }
}

struct Running {
    directory: Directory,
    anchors: Directory,
    runtime: StateRuntime,
}

fn start(index: u8, g: &Genesis, endpoints: &[String]) -> Running {
    let directory = Directory::new();
    let anchors = Directory::new();
    let history = StateHistory::create(&directory.0, &anchors.0, g.clone(), 8).unwrap();
    let signer =
        StateSigner::create(&directory.0, &anchors.0, g.clone(), consensus(index), 8).unwrap();
    let mut active = StateNetwork::new_state(transport(index), g).unwrap();
    active
        .listen_on(active.state_listen_address().unwrap().clone())
        .unwrap();
    let peers = (0..4)
        .filter(|i| *i != index)
        .map(|i| transport(i).public().to_peer_id())
        .collect();
    let initial_consensus = directory.0.join("initial-consensus.key");
    let initial_transport = directory.0.join("initial-transport.key");
    fs::write(&initial_consensus, consensus(index).to_bytes()).unwrap();
    fs::write(
        &initial_transport,
        SigningKey::from_bytes(&[201 + index; 32]).to_bytes(),
    )
    .unwrap();
    let setup = StateHandoffSetup {
        owner_key: account(index),
        candidate_family: None,
        recovery_key: None,
        recovery_endpoints: endpoints
            .iter()
            .enumerate()
            .filter(|(peer, _)| *peer != index as usize && *peer != 4 + index as usize)
            .map(|(_, endpoint)| endpoint.clone())
            .collect(),
        signer_directory: directory.0.clone(),
        signer_anchor_directory: anchors.0.clone(),
        custody_directory: directory.0.clone(),
        custody_anchor_directory: anchors.0.clone(),
        handoff_directory: directory.0.clone(),
        handoff_anchor_directory: anchors.0.clone(),
        primary_endpoint: endpoints[index as usize].clone(),
        handoff_endpoint: endpoints[4 + index as usize].clone(),
        initial_consensus_key_path: initial_consensus,
        initial_transport_key_path: initial_transport,
        primary_listen_address: None,
        handoff_listen_address: None,
    };
    let runtime = StateRuntime::new_handoff(
        history,
        Some(signer),
        StateTransportPair::new(active).unwrap(),
        peers,
        StateRuntimeConfig {
            tick_interval: Duration::from_millis(50),
            proposal_timeout: Duration::from_secs(2),
            prevote_timeout: Duration::from_secs(2),
            precommit_timeout: Duration::from_secs(2),
            allow_simulation_controls: false,
        },
        setup,
    )
    .unwrap();
    Running {
        directory,
        anchors,
        runtime,
    }
}

fn agreement(
    branch: &StateBranch,
    plan: HandoffPlan,
    keys: &[SigningKey],
    utc: u64,
) -> StateAgreement {
    let state = branch.state();
    let time = TimeCertificate::new(
        keys.iter()
            .take(3)
            .map(|key| {
                SignedTimeReport::sign(
                    state.genesis(),
                    state.authority(),
                    state.head(),
                    state.height() + 1,
                    utc,
                    key,
                )
                .unwrap()
            })
            .collect(),
        state.genesis(),
        state.authority(),
        state.head(),
        state.height() + 1,
        state.time(),
    )
    .unwrap();
    let record = state
        .prepare_record(time, Vec::new(), plan)
        .unwrap()
        .record()
        .encode()
        .unwrap();
    let proposer = branch.proposer(0, 8).unwrap().unwrap();
    let proposer_key = keys
        .iter()
        .find(|key| key.verifying_key().as_bytes() == proposer.as_bytes())
        .unwrap();
    let mut proposer_kernel = StateLockState::new(branch, proposer).unwrap();
    let intent = proposer_kernel
        .apply(
            branch,
            &StateLockEvent::Author {
                record: Some(record),
            },
            8,
        )
        .unwrap();
    let StatePublication::Proposal(proposal) = intent
        .complete(
            proposer_key
                .sign(&intent.signing_bytes().unwrap())
                .to_bytes(),
            branch,
            8,
        )
        .unwrap()
    else {
        panic!("proposal")
    };
    let proposal_bytes = proposal.encode().unwrap();
    let mut kernels: Vec<_> = keys
        .iter()
        .take(3)
        .map(|key| {
            StateLockState::new(
                branch,
                ConsensusKey::from_bytes(key.verifying_key().to_bytes()),
            )
            .unwrap()
        })
        .collect();
    let mut prevotes = Vec::new();
    for (kernel, key) in kernels.iter_mut().zip(keys) {
        let intent = kernel
            .apply(
                branch,
                &StateLockEvent::Prevote {
                    proposal: Some(proposal_bytes.clone()),
                },
                8,
            )
            .unwrap();
        let StatePublication::Vote(vote) = intent
            .complete(
                key.sign(&intent.signing_bytes().unwrap()).to_bytes(),
                branch,
                8,
            )
            .unwrap()
        else {
            panic!("prevote")
        };
        prevotes.push(vote);
    }
    let prevotes = StateQuorum::from_votes(prevotes, state.genesis(), state.authority()).unwrap();
    let mut precommits = Vec::new();
    for (kernel, key) in kernels.iter_mut().zip(keys) {
        let intent = kernel
            .apply(
                branch,
                &StateLockEvent::Precommit {
                    proposal: Some(proposal_bytes.clone()),
                    quorum: prevotes.encode(),
                },
                8,
            )
            .unwrap();
        let StatePublication::Vote(vote) = intent
            .complete(
                key.sign(&intent.signing_bytes().unwrap()).to_bytes(),
                branch,
                8,
            )
            .unwrap()
        else {
            panic!("precommit")
        };
        precommits.push(vote);
    }
    let quorum = StateQuorum::from_votes(precommits, state.genesis(), state.authority()).unwrap();
    branch.verify_agreement(&proposal, &quorum, 8).unwrap()
}

async fn seal_height(nodes: &mut [Running], keys: &[SigningKey], utc: u64) {
    seal_height_with(nodes, keys, utc, &[0, 1, 2, 3], &[0, 1, 2, 3]).await;
}

async fn seal_height_with(
    nodes: &mut [Running],
    keys: &[SigningKey],
    utc: u64,
    included: &[usize],
    recipients: &[usize],
) {
    let mut offers: Vec<_> = included
        .iter()
        .map(|index| {
            nodes[*index]
                .runtime
                .next_custody
                .as_ref()
                .unwrap()
                .offer()
                .unwrap()
                .clone()
        })
        .collect();
    offers.sort_by_key(NextPeriodKeys::unit);
    let plan = HandoffPlan::new(offers, None).unwrap();
    let agreement = agreement(nodes[0].runtime.node.branch().unwrap(), plan, keys, utc);
    let bytes = agreement.encode().unwrap();
    let previous = nodes[0].runtime.state().unwrap().height();
    for index in recipients {
        nodes[*index].runtime.node.accept_agreement(&bytes).unwrap();
    }
    let progress = tokio::time::timeout(Duration::from_secs(45), async {
        while nodes
            .iter()
            .any(|node| node.runtime.state().unwrap().height() == previous)
        {
            let (a, rest) = nodes.split_at_mut(1);
            let (b, rest) = rest.split_at_mut(1);
            let (c, d) = rest.split_at_mut(1);
            let (a, b, c, d) = tokio::join!(
                a[0].runtime.step(),
                b[0].runtime.step(),
                c[0].runtime.step(),
                d[0].runtime.step()
            );
            for (index, result) in [a, b, c, d].into_iter().enumerate() {
                result.unwrap_or_else(|error| {
                    panic!(
                        "node {index} at height {}: {error:?}",
                        nodes[index].runtime.state().unwrap().height()
                    )
                });
            }
        }
    })
    .await;
    if progress.is_err() {
        for (index, node) in nodes.iter().enumerate() {
            eprintln!(
                "node {index} height {} ready {} terminal {} active {} staged {} recovery {} flights {} queued {} recovery_flights {} authenticated {} cursor {}",
                node.runtime.state().unwrap().height(),
                node.runtime.node.ready_signatures().len(),
                node.runtime.node.terminal_signatures().len(),
                node.runtime.network.active().is_some(),
                node.runtime.network.staged().is_some(),
                node.runtime.network.recovery().is_some(),
                node.runtime.flights.len(),
                node.runtime.outbox.len(),
                node.runtime.recovery_flights.len(),
                node.runtime.recovery_authenticated.len(),
                node.runtime.recovery_cursor
            );
        }
    }
    progress.unwrap();
    assert!(
        nodes
            .iter()
            .all(|node| node.runtime.state().unwrap().height() == previous + 1)
    );
    assert!(
        nodes
            .iter()
            .all(|node| node.runtime.state().unwrap().commitment()
                == nodes[0].runtime.state().unwrap().commitment())
    );
}

#[tokio::test]
async fn localhost_handoff_rotates_twice_and_retires_old_signing_custody() {
    let endpoints = free_endpoints();
    let g = genesis_at(&endpoints);
    let mut nodes: Vec<_> = (0..4).map(|i| start(i, &g, &endpoints)).collect();
    let genesis_keys: Vec<_> = (0..4).map(consensus).collect();
    seal_height(&mut nodes, &genesis_keys, 101).await;
    for node in &nodes {
        assert!(!node.directory.0.join("initial-consensus.key").exists());
        assert!(!node.directory.0.join("initial-transport.key").exists());
        assert!(node.runtime.node.position().unwrap().is_some());
        assert!(node.runtime.current_custody.is_some());
    }
    let next_keys: Vec<_> = nodes
        .iter()
        .map(|node| {
            node.runtime
                .current_custody
                .as_ref()
                .unwrap()
                .consensus_key()
                .clone()
        })
        .collect();
    seal_height(&mut nodes, &next_keys, 102).await;
    assert!(
        nodes
            .iter()
            .all(|node| node.runtime.state().unwrap().height() == 2)
    );
    assert!(
        nodes
            .iter()
            .all(|node| node.runtime.node.position().unwrap().is_some())
    );
    for node in &nodes {
        assert!(fs::read_dir(&node.anchors.0).unwrap().count() > 0);
    }
}

#[tokio::test]
async fn cold_terminal_server_serves_final_record_to_a_late_owner() {
    let endpoints = free_endpoints();
    // The first record consumes the one ordinary slot. The next record must
    // terminate the finite run, even with no submitted research action.
    let g = genesis_at_with_run_records(&endpoints, 65);
    let mut nodes: Vec<_> = (0..4).map(|i| start(i, &g, &endpoints)).collect();
    let genesis_keys: Vec<_> = (0..4).map(consensus).collect();
    seal_height(&mut nodes, &genesis_keys, 101).await;
    assert!(
        nodes
            .iter()
            .all(|node| !node.runtime.state().unwrap().terminated())
    );

    // Pick a non-proposer as the late node so every H2 signature can come
    // from the three nodes that remain online.
    let proposer = nodes[0]
        .runtime
        .node
        .branch()
        .unwrap()
        .proposer(0, 8)
        .unwrap()
        .unwrap();
    let lagging_index = (0..4)
        .rev()
        .find(|index| {
            nodes[*index]
                .runtime
                .current_custody
                .as_ref()
                .unwrap()
                .consensus_key()
                .verifying_key()
                .as_bytes()
                != proposer.as_bytes()
        })
        .unwrap();
    let Running {
        directory: late_directory,
        anchors: late_anchors,
        mut runtime,
    } = nodes.remove(lagging_index);
    let late_consensus = runtime
        .current_custody
        .as_ref()
        .unwrap()
        .consensus_key()
        .clone();
    let late_transport = runtime
        .current_custody
        .as_ref()
        .unwrap()
        .transport_key()
        .clone();
    let late_config = runtime.config.clone();
    let late_setup = runtime.handoff_setup.take().unwrap();
    drop(runtime);

    let mut offers: Vec<_> = nodes
        .iter()
        .map(|node| {
            node.runtime
                .next_custody
                .as_ref()
                .unwrap()
                .offer()
                .unwrap()
                .clone()
        })
        .collect();
    offers.sort_by_key(NextPeriodKeys::unit);
    let plan = HandoffPlan::new(offers, None).unwrap();
    let keys: Vec<_> = nodes
        .iter()
        .map(|node| {
            node.runtime
                .current_custody
                .as_ref()
                .unwrap()
                .consensus_key()
                .clone()
        })
        .collect();
    let agreement = agreement(nodes[0].runtime.node.branch().unwrap(), plan, &keys, 102);
    assert!(agreement.state().terminated());
    let bytes = agreement.encode().unwrap();
    for node in &mut nodes {
        node.runtime.node.accept_agreement(&bytes).unwrap();
    }
    tokio::time::timeout(Duration::from_secs(45), async {
        while nodes
            .iter()
            .any(|node| node.runtime.state().unwrap().height() == 1)
        {
            let (a, rest) = nodes.split_at_mut(1);
            let (b, c) = rest.split_at_mut(1);
            let (a, b, c) = tokio::join!(
                a[0].runtime.step(),
                b[0].runtime.step(),
                c[0].runtime.step(),
            );
            a.unwrap();
            b.unwrap();
            c.unwrap();
        }
    })
    .await
    .unwrap();
    let terminal_commitment = nodes[0].runtime.state().unwrap().commitment();
    for node in &nodes {
        assert!(node.runtime.state().unwrap().terminated());
        assert_eq!(
            node.runtime.state().unwrap().commitment(),
            terminal_commitment
        );
        assert_eq!(node.runtime.position().unwrap(), None);
        assert!(node.runtime.network.active().is_none());
        assert!(node.runtime.network.staged().is_none());
        assert!(node.runtime.network.recovery().is_some());
        assert!(!node.directory.0.join("state-period-0.secret").exists());
        assert!(!node.directory.0.join("state-period-1.secret").exists());
    }

    // Shut down and reopen a completed peer before bringing the lagging node
    // back. No old authority transport remains to deliver a queued seal.
    let Running {
        directory,
        anchors,
        mut runtime,
    } = nodes.remove(0);
    let config = runtime.config.clone();
    let setup = runtime.handoff_setup.take().unwrap();
    drop(runtime);
    nodes.insert(0, reopen_on_recovery(directory, anchors, setup, config, &g));
    assert!(nodes[0].runtime.state().unwrap().terminated());

    let mut late = reopen_selected(
        late_directory,
        late_anchors,
        late_setup,
        late_config,
        &g,
        late_consensus,
        late_transport,
    );
    assert_eq!(late.runtime.state().unwrap().height(), 1);
    tokio::time::timeout(Duration::from_secs(40), async {
        while late.runtime.state().unwrap().height() == 1 {
            let (a, rest) = nodes.split_at_mut(1);
            let (b, c) = rest.split_at_mut(1);
            let (a, b, c, d) = tokio::join!(
                a[0].runtime.step(),
                b[0].runtime.step(),
                c[0].runtime.step(),
                late.runtime.step(),
            );
            a.unwrap();
            b.unwrap();
            c.unwrap();
            d.unwrap();
        }
    })
    .await
    .unwrap();
    assert!(late.runtime.state().unwrap().terminated());
    assert_eq!(
        late.runtime.state().unwrap().commitment(),
        terminal_commitment
    );
    assert_eq!(late.runtime.position().unwrap(), None);
    assert!(!late.directory.0.join("state-period-0.secret").exists());
    assert!(!late.directory.0.join("state-period-1.secret").exists());
}

#[tokio::test]
async fn vacant_owner_relays_fresh_offer_and_prepares_after_recovery_agreement() {
    let endpoints = free_endpoints();
    let g = genesis_at(&endpoints);
    let mut nodes: Vec<_> = (0..4).map(|i| start(i, &g, &endpoints)).collect();
    let genesis_proposer = nodes[0]
        .runtime
        .node
        .branch()
        .unwrap()
        .proposer(0, 8)
        .unwrap()
        .unwrap();
    let proposer_index = (0..4)
        .find(|i| consensus(*i).verifying_key().as_bytes() == genesis_proposer.as_bytes())
        .unwrap() as usize;
    let vacant = (0..4).rev().find(|i| *i != proposer_index).unwrap();
    let active: Vec<_> = (0..4).filter(|i| *i != vacant).collect();
    let genesis_keys: Vec<_> = (0..4).map(consensus).collect();
    seal_height_with(&mut nodes, &genesis_keys, 101, &active, &[0, 1, 2, 3]).await;
    assert_eq!(nodes[vacant].runtime.position().unwrap(), None);
    assert!(
        nodes[vacant]
            .runtime
            .next_custody
            .as_ref()
            .unwrap()
            .offer()
            .is_some()
    );
    let unit = nodes[vacant]
        .runtime
        .state()
        .unwrap()
        .authority()
        .owner(AccountId::for_key(
            account(vacant as u8).verifying_key().as_bytes(),
        ))
        .unwrap()
        .id();
    let relay = tokio::time::timeout(Duration::from_secs(40), async {
        while active
            .iter()
            .all(|index| !nodes[*index].runtime.offers.contains_key(&unit))
        {
            let (a, rest) = nodes.split_at_mut(1);
            let (b, rest) = rest.split_at_mut(1);
            let (c, d) = rest.split_at_mut(1);
            let (a, b, c, d) = tokio::join!(
                a[0].runtime.step(),
                b[0].runtime.step(),
                c[0].runtime.step(),
                d[0].runtime.step()
            );
            a.unwrap();
            b.unwrap();
            c.unwrap();
            d.unwrap();
        }
    })
    .await;
    if relay.is_err() {
        for (index, node) in nodes.iter().enumerate() {
            eprintln!(
                "relay node {index} height {} recovery-auth {} clients {} offers {} outbox {} flights {} recovery-flights {}",
                node.runtime.state().unwrap().height(),
                node.runtime.recovery_authenticated.len(),
                node.runtime.recovery_clients.len(),
                node.runtime.offers.len(),
                node.runtime.outbox.len(),
                node.runtime.flights.len(),
                node.runtime.recovery_flights.len()
            );
        }
    }
    relay.unwrap();
    let selected_proposer = nodes[0]
        .runtime
        .node
        .branch()
        .unwrap()
        .proposer(0, 8)
        .unwrap()
        .unwrap();
    let selected_proposer_index = active
        .iter()
        .copied()
        .find(|i| {
            nodes[*i]
                .runtime
                .current_custody
                .as_ref()
                .unwrap()
                .consensus_key()
                .verifying_key()
                .as_bytes()
                == selected_proposer.as_bytes()
        })
        .unwrap();
    let omitted = active
        .iter()
        .copied()
        .find(|i| *i != selected_proposer_index)
        .unwrap();
    let next_offers: Vec<_> = (0..4).filter(|i| *i != omitted).collect();
    let current_keys: Vec<_> = active
        .iter()
        .map(|index| {
            nodes[*index]
                .runtime
                .current_custody
                .as_ref()
                .unwrap()
                .consensus_key()
                .clone()
        })
        .collect();
    seal_height_with(&mut nodes, &current_keys, 102, &next_offers, &active).await;
    assert!(nodes[vacant].runtime.position().unwrap().is_some());
    assert!(nodes[vacant].runtime.current_custody.is_some());
    assert_eq!(nodes[vacant].runtime.state().unwrap().height(), 2);
}

#[tokio::test]
async fn newly_vacant_sole_finality_holder_relays_to_prepared_peers() {
    let endpoints = free_endpoints();
    let g = genesis_at(&endpoints);
    let mut nodes: Vec<_> = (0..4).map(|i| start(i, &g, &endpoints)).collect();
    let mut offers: Vec<_> = (1..4)
        .map(|index| {
            nodes[index]
                .runtime
                .next_custody
                .as_ref()
                .unwrap()
                .offer()
                .unwrap()
                .clone()
        })
        .collect();
    offers.sort_by_key(NextPeriodKeys::unit);
    let plan = HandoffPlan::new(offers, None).unwrap();
    let keys: Vec<_> = (0..4).map(consensus).collect();
    let branch = nodes[0].runtime.node.branch().unwrap();
    let agreement = agreement(branch, plan, &keys, 101);
    let signature = |role: SealRole, signer: &SigningKey| {
        let key = ConsensusKey::from_bytes(signer.verifying_key().to_bytes());
        SealSignature::complete(
            role,
            agreement.seal_context(),
            key,
            signer
                .sign(&SealSignature::signing_bytes(
                    role,
                    agreement.seal_context(),
                    key,
                ))
                .to_bytes(),
            agreement.outgoing(),
            agreement.incoming(),
        )
        .unwrap()
    };
    let ready: Vec<_> = (1..4)
        .map(|index| {
            signature(
                SealRole::Ready,
                nodes[index]
                    .runtime
                    .next_custody
                    .as_ref()
                    .unwrap()
                    .consensus_key(),
            )
        })
        .collect();
    let terminal: Vec<_> = (0..3)
        .map(|index| signature(SealRole::Terminal, &keys[index]))
        .collect();
    let seal = StateSeal::new(
        ready,
        terminal,
        agreement.seal_context(),
        agreement.outgoing(),
        agreement.incoming(),
    )
    .unwrap();
    let finalized = branch
        .verify_finality(agreement.proposal(), agreement.quorum(), &seal, 8)
        .unwrap()
        .encode()
        .unwrap();

    // The old owner 0 alone receives the completed seal. Its slot is vacant
    // in the successor, while peers 1 and 2 only know the prepared agreement.
    for node in nodes.iter_mut().take(3).skip(1) {
        node.runtime
            .node
            .accept_agreement(&agreement.encode().unwrap())
            .unwrap();
    }
    assert_eq!(
        nodes[0].runtime.node.accept_finality(&finalized).unwrap(),
        StateAppendOutcome::Finalized
    );
    nodes[0].runtime.on_height().unwrap();
    assert!(nodes[0].runtime.network.active().is_none());
    for node in nodes.iter().take(3).skip(1) {
        assert_eq!(node.runtime.state().unwrap().height(), 0);
        assert!(node.runtime.node.handoff_agreement().is_some());
    }

    tokio::time::timeout(Duration::from_secs(35), async {
        while (1..3).any(|index| nodes[index].runtime.state().unwrap().height() == 0) {
            let (vacant, rest) = nodes.split_at_mut(1);
            let (first, rest) = rest.split_at_mut(1);
            let (second, _) = rest.split_at_mut(1);
            let (vacant, first, second) = tokio::join!(
                vacant[0].runtime.step(),
                first[0].runtime.step(),
                second[0].runtime.step(),
            );
            vacant.unwrap();
            first.unwrap();
            second.unwrap();
        }
    })
    .await
    .unwrap();
    let final_commitment = nodes[0].runtime.state().unwrap().commitment();
    for node in nodes.iter().take(3).skip(1) {
        assert_eq!(node.runtime.state().unwrap().height(), 1);
        assert_eq!(node.runtime.state().unwrap().commitment(), final_commitment);
    }
}

#[tokio::test]
async fn simulated_isolation_blocks_owner_authenticated_recovery_routes() {
    let endpoints = free_endpoints();
    let g = genesis_at(&endpoints);
    let mut node = start(0, &g, &endpoints);
    node.runtime.config.allow_simulation_controls = true;
    let local = AccountId::for_key(account(0).verifying_key().as_bytes());
    let remotes: Vec<_> = node
        .runtime
        .state()
        .unwrap()
        .authority()
        .units()
        .iter()
        .filter(|unit| unit.owner() != local)
        .map(|unit| (unit.slot(), unit.owner()))
        .collect();
    for (slot, _) in &remotes {
        node.runtime.set_slot_enabled(*slot, false).unwrap();
    }
    assert!(node.runtime.all_remote_slots_disabled().unwrap());
    for (_, owner) in &remotes {
        assert!(node.runtime.recovery_owner_disabled(*owner).unwrap());
    }
    let peer = transport(1).public().to_peer_id();
    node.runtime.recovery_authenticated.insert(peer);
    node.runtime.recovery_clients.insert(peer);
    node.runtime.apply_slot_disables().unwrap();
    assert!(node.runtime.recovery_authenticated.is_empty());
    assert!(node.runtime.recovery_clients.is_empty());
    let cursor = node.runtime.recovery_cursor;
    node.runtime.probe_recovery().unwrap();
    assert_eq!(node.runtime.recovery_cursor, cursor);
    node.runtime.set_slot_enabled(remotes[0].0, true).unwrap();
    assert!(!node.runtime.all_remote_slots_disabled().unwrap());
}
