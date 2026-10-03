//! Fixed-input, discrete-event control; not a proposed wire protocol.
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use naome_checker::normalize_and_check;
use naome_foundation::{Formula, FreeVariable};
use naome_proof::{ProofCertificate, ProofStep};
use sha2::{Digest, Sha256};

const GENESIS: [u8; 32] = [42; 32];
const MAX_BLOCKS: usize = 1024;
const MAX_EVENTS: usize = 4096;
const BATCH: usize = 16;
type Id = [u8; 32];

#[derive(Clone)]
struct Block {
    id: Id,
    genesis: Id,
    parent: usize,
    parent_id: Id,
    height: usize,
    nonce: u64,
    proof_id: Id,
    proof: Vec<u8>,
}

impl Block {
    fn digest(&self) -> Id {
        let mut hash = Sha256::new();
        hash.update(b"naome:height-gossip-experiment:v1\0");
        hash.update(self.genesis);
        hash.update(self.parent_id);
        hash.update((self.height as u64).to_be_bytes());
        hash.update(self.nonce.to_be_bytes());
        hash.update(self.proof_id);
        hash.update((self.proof.len() as u64).to_be_bytes());
        hash.update(&self.proof);
        hash.finalize().into()
    }
    fn bytes(&self) -> usize {
        32 * 4 + 8 * 3 + self.proof.len()
    }
}

fn proof(nonce: u64) -> (Id, Vec<u8>) {
    let variable = FreeVariable::new(0);
    let atom = Formula::equal(variable, variable);
    // An injective structural family of cheap logical tautologies. These are
    // real checked proofs, but not admitted research questions or useful work.
    let mut formula = Formula::implies(atom.clone(), atom.clone());
    for bit in 0..16 {
        formula = if nonce & (1 << bit) == 0 {
            Formula::implies(formula, atom.clone())
        } else {
            Formula::implies(atom.clone(), formula)
        };
    }
    let certificate = ProofCertificate::new(vec![
        ProofStep::Simplification {
            antecedent: formula.into(),
            consequent: atom.into(),
        },
        ProofStep::Generalization {
            premise: 0,
            variable,
        },
    ])
    .unwrap();
    let checked = normalize_and_check(certificate).unwrap();
    (
        *checked.proof_id().as_bytes(),
        checked.normal_form().canonical_bytes().to_vec(),
    )
}

#[derive(Default)]
struct Node {
    known: BTreeSet<usize>,
    tip: usize,
    confirmed: Vec<usize>,
    observed: BTreeMap<usize, BTreeSet<Id>>,
    max_reorg: usize,
    revoked: usize,
    invalid_rejected: usize,
    policy_rejected: usize,
    lock_rejected: usize,
    duplicates: usize,
    orphans: usize,
}

fn path(blocks: &[Block], mut tip: usize) -> Vec<usize> {
    let mut result = Vec::new();
    while tip != 0 {
        result.push(tip);
        tip = blocks[tip].parent;
        assert!(result.len() <= MAX_BLOCKS);
    }
    result.reverse();
    result
}

impl Node {
    fn new() -> Self {
        Self {
            known: BTreeSet::from([0]),
            ..Self::default()
        }
    }
    fn receive(&mut self, index: usize, blocks: &[Block], restricted: bool) {
        if self.known.contains(&index) {
            self.duplicates += 1;
            return;
        }
        let block = &blocks[index];
        if !self.known.contains(&block.parent) {
            // No unbounded orphan cache. The next inventory exchange retries.
            self.orphans += 1;
            return;
        }
        let valid = block.genesis == GENESIS
            && block.parent_id == blocks[block.parent].id
            && block.height == blocks[block.parent].height + 1
            && block.digest() == block.id
            && ProofCertificate::from_canonical_bytes(&block.proof)
                .ok()
                .and_then(|p| normalize_and_check(p).ok())
                .is_some_and(|p| {
                    p.proof_id().as_bytes() == &block.proof_id
                        && p.normal_form().canonical_bytes() == block.proof
                })
            && path(blocks, block.parent)
                .iter()
                .all(|&p| blocks[p].proof_id != block.proof_id);
        if !valid {
            self.invalid_rejected += 1;
            return;
        }
        if restricted && block.nonce >= 1000 {
            self.policy_rejected += 1;
            return;
        }
        assert!(self.known.len() < MAX_BLOCKS);
        self.known.insert(index);
    }
    fn select(&mut self, blocks: &[Block], depth: usize, lock: bool) {
        let mut candidates: Vec<_> = self.known.iter().copied().collect();
        candidates.sort_by_key(|&i| (std::cmp::Reverse(blocks[i].height), blocks[i].id));
        let selected = candidates.into_iter().find(|&i| {
            if !lock {
                return true;
            }
            let compatible = path(blocks, i).starts_with(&self.confirmed);
            if !compatible {
                self.lock_rejected += 1;
            }
            compatible
        });
        let old = path(blocks, self.tip);
        self.tip = selected.expect("current tip always remains compatible");
        let new = path(blocks, self.tip);
        let common = old.iter().zip(&new).take_while(|(a, b)| a == b).count();
        self.max_reorg = self.max_reorg.max(old.len() - common);
        let prefix = new[..new.len().saturating_sub(depth)].to_vec();
        self.revoked += self
            .confirmed
            .iter()
            .enumerate()
            .filter(|&(height, id)| prefix.get(height) != Some(id))
            .count();
        self.confirmed = prefix;
        for (height, &i) in self.confirmed.iter().enumerate() {
            self.observed
                .entry(height + 1)
                .or_default()
                .insert(blocks[i].id);
        }
    }
}

struct Event {
    at: usize,
    from: usize,
    to: usize,
    blocks: Vec<usize>,
}
struct Rng(u64);
impl Rng {
    fn pick(&mut self, bound: usize) -> usize {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        ((z ^ (z >> 31)) % bound as u64) as usize
    }
}

fn connected(
    scenario: &str,
    topology: &str,
    tick: usize,
    release: usize,
    n: usize,
    a: usize,
    b: usize,
) -> bool {
    if a == b {
        return false;
    }
    if scenario == "partition" && tick < release && (a < n / 2) != (b < n / 2) {
        return false;
    }
    if scenario == "restart" && tick < release && (a == n - 1 || b == n - 1) {
        return false;
    }
    if scenario == "eclipse" && ((a == n - 1 && b != n / 2) || (b == n - 1 && a != n / 2)) {
        return false;
    }
    topology != "ring" || (a + 1) % n == b || (b + 1) % n == a
}

fn add_block(blocks: &mut Vec<Block>, parent: usize, nonce: u64) -> usize {
    assert!(blocks.len() < MAX_BLOCKS);
    let (proof_id, proof) = proof(nonce);
    let mut block = Block {
        id: [0; 32],
        genesis: GENESIS,
        parent,
        parent_id: blocks[parent].id,
        height: blocks[parent].height + 1,
        nonce,
        proof_id,
        proof,
    };
    block.id = block.digest();
    blocks.push(block);
    blocks.len() - 1
}

fn conflict_pairs(nodes: &[Node], blocks: &[Block], ever: bool) -> usize {
    let mut conflicts = 0;
    for (i, left) in nodes.iter().enumerate() {
        for right in &nodes[i + 1..] {
            let different = if ever {
                left.observed.iter().any(|(h, ids)| {
                    right.observed.get(h).is_some_and(|others| {
                        ids.iter().any(|id| others.iter().any(|other| id != other))
                    })
                })
            } else {
                left.confirmed
                    .iter()
                    .zip(&right.confirmed)
                    .any(|(&a, &b)| blocks[a].id != blocks[b].id)
            };
            conflicts += usize::from(different);
        }
    }
    conflicts
}

fn conflict_witness(nodes: &[Node], blocks: &[Block], tick: usize) -> Option<String> {
    for (left, a) in nodes.iter().enumerate() {
        for (right, b) in nodes.iter().enumerate().skip(left + 1) {
            for (height, (&x, &y)) in a.confirmed.iter().zip(&b.confirmed).enumerate() {
                if blocks[x].id != blocks[y].id {
                    let hex = |id: Id| id.iter().map(|b| format!("{b:02x}")).collect::<String>();
                    return Some(format!(
                        "{{\"tick\":{tick},\"height\":{},\"left_node\":{left},\"right_node\":{right},\"left_id\":\"{}\",\"right_id\":\"{}\"}}",
                        height + 1,
                        hex(blocks[x].id),
                        hex(blocks[y].id)
                    ));
                }
            }
        }
    }
    None
}

pub fn run() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(
        args.len(),
        8,
        "nodes depth seed scenario reversible|lock delay random|ring"
    );
    let n: usize = args[1].parse().unwrap();
    let depth: usize = args[2].parse().unwrap();
    let seed: u64 = args[3].parse().unwrap();
    let scenario = args[4].as_str();
    assert!(matches!(
        scenario,
        "ordinary"
            | "equal"
            | "delayed"
            | "partition"
            | "withholding"
            | "duplicates"
            | "invalid"
            | "cheap"
            | "sybil"
            | "eclipse"
            | "restart"
            | "policy"
    ));
    assert!(matches!(args[5].as_str(), "reversible" | "lock"));
    let lock = args[5] == "lock";
    let delay: usize = args[6].parse().unwrap();
    let topology = args[7].as_str();
    assert!(matches!(topology, "random" | "ring"));
    assert!([4, 8, 16].contains(&n) && (1..=100).contains(&depth) && (1..=20).contains(&delay));
    let started = Instant::now();
    let mut rng = Rng(seed);
    let mut blocks = vec![Block {
        id: GENESIS,
        genesis: GENESIS,
        parent: 0,
        parent_id: GENESIS,
        height: 0,
        nonce: 0,
        proof_id: [0; 32],
        proof: Vec::new(),
    }];
    let length = depth + 5;
    let mut a = Vec::new();
    let mut b = Vec::new();
    let mut parent = 0;
    for h in 0..length {
        parent = add_block(&mut blocks, parent, h as u64 + 1);
        a.push(parent);
    }
    let forks = matches!(
        scenario,
        "equal" | "partition" | "withholding" | "cheap" | "sybil" | "eclipse" | "policy"
    );
    if forks {
        parent = 0;
        let extra = usize::from(matches!(scenario, "partition" | "withholding" | "policy"));
        let b_length = if matches!(scenario, "cheap" | "sybil" | "eclipse") {
            2 * length
        } else {
            length + extra
        };
        for h in 0..b_length {
            parent = add_block(&mut blocks, parent, h as u64 + 1000);
            b.push(parent);
        }
    }
    assert_eq!(
        blocks[1..]
            .iter()
            .map(|b| b.proof_id)
            .collect::<BTreeSet<_>>()
            .len(),
        blocks.len() - 1
    );
    let mut injected = Vec::new();
    if scenario == "invalid" {
        let mut bad = blocks[a[0]].clone();
        // Structurally canonical, mathematically false inference.
        bad.proof = ProofCertificate::new(vec![
            ProofStep::EqualityReflexivity {
                variable: FreeVariable::new(0),
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 0,
            },
        ])
        .unwrap()
        .into_unchecked_normal_form()
        .canonical_bytes()
        .to_vec();
        bad.id = bad.digest();
        blocks.push(bad);
        injected.push(blocks.len() - 1);
        // Replay, hash, genesis, height and duplicate-proof binding controls.
        for kind in 0..4 {
            let mut bad = blocks[a[0]].clone();
            match kind {
                0 => bad.genesis = [41; 32],
                1 => bad.height = 999,
                2 => bad.parent_id = [9; 32],
                _ => {
                    bad.parent = a[0];
                    bad.parent_id = blocks[a[0]].id;
                    bad.height = 2;
                }
            }
            bad.id = bad.digest();
            blocks.push(bad);
            injected.push(blocks.len() - 1);
        }
        let mut bad = blocks[a[0]].clone();
        bad.id = [1; 32];
        blocks.push(bad);
        injected.push(blocks.len() - 1);
    }
    let mut nodes: Vec<_> = (0..n).map(|_| Node::new()).collect();
    let release = length + 2;
    let production_end = release + 1;
    let horizon = production_end + 128 + 16 * n + 4 * delay;
    let mut events: Vec<Event> = Vec::new();
    let mut messages = 0usize;
    let mut bytes = 0usize;
    let mut queue_peak = 0usize;
    let mut queue_dropped = 0usize;
    let mut partition_conflicts = 0usize;
    let mut convergence = None;
    let mut restart_snapshot = None;
    let mut witness = None;
    for tick in 0..horizon {
        if tick < length {
            nodes[0].receive(a[tick], &blocks, false);
            if forks && !matches!(scenario, "withholding" | "cheap" | "sybil" | "eclipse") {
                nodes[n / 2].receive(b[tick], &blocks, false);
            }
        }
        if scenario == "partition" && tick == length {
            nodes[n / 2].receive(b[length], &blocks, false);
        }
        if tick == release
            && matches!(
                scenario,
                "withholding" | "cheap" | "sybil" | "eclipse" | "policy"
            )
        {
            for &index in &b {
                nodes[n / 2].receive(index, &blocks, false);
            }
        }
        if scenario == "invalid" && tick == 2 {
            for node in &mut nodes {
                for &index in &injected {
                    node.receive(index, &blocks, false);
                }
            }
        }
        if scenario == "duplicates" && tick < length {
            for _ in 0..8 {
                nodes[0].receive(a[tick], &blocks, false);
            }
        }
        if scenario == "restart" && tick == release {
            // Process restart reconstructs from retained block inputs, tip and
            // lock through the same checking path. No disk durability claim.
            restart_snapshot = Some(nodes[n - 1].known.clone());
            let saved = nodes[0].known.clone();
            let confirmed = nodes[0].confirmed.clone();
            let old_tip = nodes[0].tip;
            let mut replayed = Node::new();
            let mut ordered: Vec<_> = saved.into_iter().filter(|&i| i != 0).collect();
            ordered.sort_by_key(|&i| blocks[i].height);
            for i in ordered {
                replayed.receive(i, &blocks, false);
            }
            replayed.confirmed = confirmed;
            replayed.tip = old_tip;
            assert_eq!(replayed.known, nodes[0].known);
            // Keep observations and counters across the simulated restart.
            nodes[0].known = replayed.known;
        }
        let mut future = Vec::new();
        for event in events.drain(..) {
            if event.at > tick {
                future.push(event);
                continue;
            }
            if !connected(scenario, topology, tick, release, n, event.from, event.to) {
                continue;
            }
            for index in event.blocks {
                nodes[event.to].receive(index, &blocks, scenario == "policy" && event.to < n / 2);
            }
        }
        events = future;
        for node in &mut nodes {
            node.select(&blocks, depth, lock);
        }
        if witness.is_none() {
            witness = conflict_witness(&nodes, &blocks, tick);
        }
        if tick + 1 == release {
            partition_conflicts = conflict_pairs(&nodes, &blocks, false);
        }
        if tick >= production_end {
            if nodes.iter().all(|node| node.tip == nodes[0].tip) {
                convergence.get_or_insert(tick - production_end);
            } else {
                convergence = None;
            }
        }
        for from in 0..n {
            let peers: Vec<_> = (0..n)
                .filter(|&to| connected(scenario, topology, tick, release, n, from, to))
                .collect();
            if peers.is_empty() {
                continue;
            }
            // Identity multiplicity only biases peer sampling. It has no vote
            // weight. "sybil" assigns 100 endpoint tickets to the attacker.
            let mut tickets = peers.clone();
            if scenario == "sybil" && peers.contains(&(n / 2)) {
                tickets.extend(std::iter::repeat_n(n / 2, 100));
            }
            let to = tickets[rng.pick(tickets.len())];
            // Atomic inventory abstraction, both inventories charged in bytes.
            // Delay applies to block delivery; stale inventories and transport
            // framing must be tested by a future real networking experiment.
            let mut missing: Vec<_> = nodes[from]
                .known
                .difference(&nodes[to].known)
                .copied()
                .collect();
            missing.sort_by_key(|&i| (blocks[i].height, blocks[i].id));
            missing.truncate(BATCH);
            bytes += 64 + 32 * (nodes[from].known.len() + nodes[to].known.len());
            bytes += missing.iter().map(|&i| blocks[i].bytes()).sum::<usize>();
            messages += 3; // two inventories and one bounded block response
            if events.len() == MAX_EVENTS {
                queue_dropped += 1;
                continue;
            }
            let at = tick + 1 + rng.pick(delay);
            events.push(Event {
                at,
                from,
                to,
                blocks: missing,
            });
            queue_peak = queue_peak.max(events.len());
        }
    }
    let mut input_hash = Sha256::new();
    for block in &blocks[1..] {
        input_hash.update(block.id);
        input_hash.update(&block.proof);
    }
    let input_digest: String = input_hash
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let total = |f: fn(&Node) -> usize| nodes.iter().map(f).sum::<usize>();
    let tips: BTreeSet<_> = nodes.iter().map(|node| blocks[node.tip].id).collect();
    let initial_catchup = restart_snapshot.as_ref().map_or(0, BTreeSet::len);
    let witness = witness.unwrap_or("null".into());
    let attack_tips = nodes
        .iter()
        .filter(|node| blocks[node.tip].nonce >= 1000)
        .count();
    println!(
        "{{\"schema\":1,\"nodes\":{n},\"depth\":{depth},\"seed\":{seed},\"scenario\":\"{scenario}\",\"mode\":\"{}\",\"delay\":{delay},\"topology\":\"{topology}\",\"input_sha256\":\"{input_digest}\",\"blocks\":{},\"messages\":{messages},\"modeled_bytes\":{bytes},\"ticks\":{horizon},\"convergence_ticks\":{},\"selected_tips\":{},\"ever_conflicting_pairs\":{},\"current_conflicting_pairs\":{},\"pre_rejoin_conflicting_pairs\":{partition_conflicts},\"max_reorg\":{},\"revoked_confirmations\":{},\"invalid_rejected\":{},\"invalid_accepted\":{},\"policy_rejected\":{},\"lock_rejected\":{},\"duplicates\":{},\"orphan_retries\":{},\"queue_peak\":{queue_peak},\"queue_dropped\":{queue_dropped},\"pending_at_horizon\":{},\"initial_catchup_blocks\":{initial_catchup},\"conflict_witness\":{witness},\"selected_second_branch_nodes\":{attack_tips},\"elapsed_micros\":{}}}",
        if lock { "lock" } else { "reversible" },
        blocks.len() - 1,
        convergence.map_or("null".into(), |t| t.to_string()),
        tips.len(),
        conflict_pairs(&nodes, &blocks, true),
        conflict_pairs(&nodes, &blocks, false),
        nodes.iter().map(|node| node.max_reorg).max().unwrap(),
        total(|node| node.revoked),
        total(|node| node.invalid_rejected),
        nodes
            .iter()
            .map(|node| injected.iter().filter(|i| node.known.contains(i)).count())
            .sum::<usize>(),
        total(|node| node.policy_rejected),
        total(|node| node.lock_rejected),
        total(|node| node.duplicates),
        total(|node| node.orphans),
        events.len(),
        started.elapsed().as_micros()
    );
}
