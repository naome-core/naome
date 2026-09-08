# Fixed-validator V0 Byzantine process partition

## Contract and authority

`SEC-012-006` refines the existing Byzantine bridge case in
[the driver corpus](fixed-validator-partition-simulation-v0.md) using four
actual Unix `naome-validator` processes and one test-controlled Byzantine peer.
It adds finite integration evidence and no production behavior. Each honest
process owns its original signing scope and independent anchored finality and
vote journals throughout the execution.

The four honest consensus keys have weight two each. The separate faulty key
has weight three, strictly below one third of immutable total weight eleven.
The actual weighted schedule must select that faulty key at H1/R0 and an honest
key at H1/R1. The two honest groups are `{0,1}` and `{2,3}`. During partition,
each group can receive at most its own weight four plus the faulty key's weight
three. `3 * 7 <= 2 * 11` forbids finality even though the faulty key appears in
both groups. After healing, the honest weight eight alone satisfies
`3 * 8 > 2 * 11`.

Every honest process lists only the bridge as its configured Noise/Yamux peer
and publication target. There is no direct honest-to-honest path. The bridge
forwards exact captured honest publications within each group, permanently
drops cross-group publications during partition, and forwards new publications
to all honest recipients after explicit healing. Each forwarded or injected
message is sent twice through separately correlated transport requests.
Transport receipt alone is not consensus admission or signed-weight evidence.

Only the designated faulty key creates raw test signatures. It authorizes two
distinct valid artifacts with the same virtual-genesis parent at H1/R0, sends
one proposal to each group, and equivocates its own proposal prevotes and
precommits accordingly. The harness verifies these inputs before delivery.
Honest private keys are used only to provision their processes and for strict
stopped-journal inspection; the harness never uses them to manufacture a
proposal, vote, quorum, or recovery action.

## Partition and healing oracles

Both conflicting proposals must cause real honest proposal prevotes for their
respective values. Before round advancement, each process must report successful
admission of the exact proposal through both current proposal routes, its local
prevote, its partner's prevote, and the faulty key's prevote and precommit.
Diagnostic SHA-256 fingerprints bind peer reports to the already verified
canonical bytes. Local admission is correlated within the single outstanding
publication's interval to its completed-publication fingerprint; the local
admission report itself intentionally carries no copied input bytes. Peer
labels and repeated receipts never supply additional consensus keys or weight.

Every honest process must emit a real nil precommit after its prevote deadline
and reach H1/R1 Proposal through its admitted precommit deadline. Before healing,
no process may report finality, and every finality journal and anchor must remain
byte-identical to its initialized baseline. All four processes remain alive;
the test injects no driver event, timeout ticket, certificate, or selected state.

Healing leaves the faulty key silent and does not replay the dropped messages.
The harness supplies one ordinary `author_fresh` command to the actual H1/R1
honest proposer for the first artifact. All four processes must publish their
own proposal prevote and precommit, finalize that artifact, and drain the
bridge's delivery custody. Thus broken delivery cannot satisfy the negative
partition result without failing the same execution's positive control.

## Signed history and strict replay

Captured honest votes are strictly verified against their actual key, context,
height, round, role, and target. One key/height/round/role slot may repeat only
with identical canonical bytes. The execution requires the sixteen expected
H1 votes: four proposal prevotes and four nil precommits in R0, followed by four
proposal prevotes and four proposal precommits in R1.

Normal shutdown must release each process's ownership and exit successfully.
Only after the children stop does the parent open the anchored journals under
the existing spawn/journal guard. Strict replay requires one H1/R1 finality
record with the exact artifact, payload, artifact-set root, virtual-genesis
parent, and common ancestry. Its precommit certificate must be byte-identical
to the certificate reconstructed from all four captured honest R1 precommits,
with exactly four distinct keys and signed weight eight of total eleven.
Every retained H1 vote must match its captured signed bytes, and inspection
refuses additional completed vote slots through H2/R4. Complete authority images
must remain unchanged by inspection; replay cannot hide a repaired tail.

## Bounds and evidence limits

This is one finite local Unix process/loopback execution with five fixed keys,
two values, one height, and two observed rounds. Test-local phase bases are ten
seconds plus one millisecond per round. Each milestone has the existing
45-second bound. Each honest inbox has 128 entries and 1 MiB; driver and recovery
round ceilings are four, finality replay ceiling eight, vote preparation bound
64, and proposal preparation bound eight. The bridge has at most 128 queued
messages per recipient, one active outbound request per peer, 64 captured vote
slots, 16 captured proposal publications, and 512 completed deliveries.

The test does not claim arbitrary Byzantine schedules, physical TCP cuts,
reconnection, crash/restart, partial writes, dynamic validators, general safety
or liveness, deployment, or production readiness. The separate honest physical
partition and process-kill corpora retain their own evidence boundaries.
`SEC-012` remains `IN_PROGRESS`.
