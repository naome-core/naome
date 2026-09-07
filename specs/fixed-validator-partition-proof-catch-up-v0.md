# Fixed-validator V0 partition, proof catch-up and renewed voting

## Contract

`PROD-020-061` integrates the existing partition, live proof-provider, bounded
validator catch-up, anchored signer and publication-recovery contracts. It adds
two finite Unix process executions and no production behavior or policy.
The test is `crates/naome-validator/tests/cases/partition_proof_catch_up.rs`.

Four independently anchored validator processes create every proposal, vote
and complete proof through ordinary consensus. The harness supplies three
`author_fresh` commands, opaque TCP connection cuts and reopening, explicit
single-height `sync_finality` commands choosing one configured peer, and normal
shutdown. One execution additionally kills and reaps a minority process and
explicitly reopens it. The serving process uses its opt-in retained-proof
provider. No prepared proof fixture, raw signed-message injection, direct
journal installation, selected checkpoint, fabricated honest signature, inbox
disposal or timeout injection supplies the result.

## Partition and catch-up

The raw-key-sorted immutable weights are `[3, 2, 1, 1]`, with total weight seven.
The complete authenticated mesh first finalizes one common H1 artifact and
drains its publications. Opaque gates then divide the owners into `{3,2}` and
`{1,1}` components and both endpoints must observe each cut before H2 authoring.
Only the weight-five component can strictly exceed two thirds of the immutable
total. It produces and retains H2 finality through real proposal, prevote and
precommit exchange. Both minority owners retain the exact H1 finality journal
and anchor through actual deadlines and durable H2/R1 nil prevoting. Their
observed peer admissions remain inside the minority component during isolation.

All original caller proposal files are deleted after these milestones. In the
crash execution, the future H3 proposer is killed at this completed later-round
checkpoint, with its publications drained. OS-reported SIGKILL termination and
reaping precede strict stopped-owner inspection. The saved signature oracle
verifies completed slots by actual key, context, height, round and role and
retains both original canonical bytes and completion identities. Reopen restores
H2/R1 Prevote and H1 finality with empty volatile inboxes and no catch-up job;
strict inspection and the initial ready checkpoint leave authority images
unchanged. The other three original processes remain alive.

After gates reopen, both endpoints of every mesh edge must report an established
session before catch-up, so the later cut starts from verified connections.
Managed reconnection and retained-publication processing continue ordinarily.
Before each catch-up command, the minority still owns H2
at a round above zero with the exact H1 finality images. Thus stale R0 raw
messages cannot substitute for the measured complete-proof operation. Each
minority explicitly requests exactly one height from the same live weight-three
provider. Its queued response, exact job completion, H2 finality and new H3/R0
Proposal state are observed separately. Strict stopped replay later requires
the minorities to retain the provider's exact first H2 envelope, including its
original evidence, rather than only the same selected artifact.

## Necessary renewed participation

For H3 the weight-two validator is temporarily isolated. The available
`{3,1,1}` component has weight five, but either minority's absence leaves only
four: `3 * 4 <= 2 * 7`. Both caught-up validators are therefore necessary for
the new strict quorum. The recovered weight-one scheduled proposer authors H3
through the ordinary command. Each available owner must admit its own proposal
prevote and non-nil precommit before the component reaches H3 finality.

Reopening the final paths permits the ordinary managed publication replay to
deliver H3 to the weight-two owner as well. All four then shut down normally
with released locks. Strict replay checks three exact artifacts and payloads,
the artifact-set root, identical consensus ancestry, and preservation of each
owner's original H1 journal prefix. The signed-message oracle verifies both
minorities' actual H3/R0 proposal-target prevotes and precommits and the recovered
proposer's H3 authorization. Their H2 votes remain nil; proof catch-up grants no
retroactive vote. In the crash execution every saved completion identity and
canonical message remains byte-identical after restart, catch-up and renewed
signing.

## Bounds and evidence limits

The majority uses 120-second phase bases and the minority uses five-second
bases, each plus one millisecond per round. These explicit fixture values keep
the majority's next-height proposer schedule stable while real minority
deadlines advance; they are not production timing recommendations. Existing
45-second milestone, 4,096-event transcript, bounded opaque gate workers,
inboxes and persisted preparation/replay limits remain enforced. Every healed
cross-component path must forward a new connection after having refused actual
redials while isolated.

These are two bounded loopback network executions. They establish actual
consensus production followed by explicit proof catch-up and necessary resumed
signing, including one process kill. They do not establish arbitrary partition
healing or scheduling, general distributed safety or liveness, automatic proof
acquisition or job resumption, dynamic-validator transitions, power-loss or
partial-write recovery, production custody, or deployment readiness. `PROD-020`
remains `IN_PROGRESS`; the narrower previously implemented components retain
their own authority and evidence boundaries.
