# Fixed-validator V0 partition simulation

## Selected property and boundary

`SEC-012-001` and `TEST-010` verify the existing artifact-only fixed-validator V0
driver in the finite delivery schedules below. A recipient must not finalize a new value
without having received distinct authenticated precommits for that value and
round with weight strictly greater than two thirds of the immutable total.
Honest recipients must not select different values at the same height. A
partition does not reduce the denominator, relax the threshold, or grant a
timeout finality authority.

The simulation starts with four independently provisioned honest drivers at
H1/R0, empty vote/proposal histories, and no cached quorum certificate. Each
driver owns its original anchored signing scope for the complete execution.
Cold partitions begin before proposal delivery. The separate precommit-cut
scenarios deliver the proposal and prevotes while connected, then withhold
cross-partition precommits; they can have real prevote quorums and non-nil
precommit publications when finality delivery is cut.

This starting condition matters: a previously available complete valid
precommit proof retains its authority even if its recipient subsequently loses
contact with the signers. The selected property does not forbid such finality.
"Halts finality" here means absence of a new finality transition without usable
strict-quorum evidence. Honest timeout progression and nil votes remain allowed;
this is not a durable terminal halt.

The simulation grants no production authority and changes no production API,
signing, persistence, wire, proposer, quorum, or finality rule. `SEC-012` remains
`IN_PROGRESS`; general safety and liveness requirements remain separate.

## Executions

All weights are assigned after sorting the actual raw consensus keys. Each
row executes twice: FIFO delivery once per envelope, and reverse delivery with
two copies of every admitted envelope. The reversed order applies within phase
waves, not across arbitrary phase or round boundaries.

| Scenario | Weights | Honest groups | Required partition result |
| --- | --- | --- | --- |
| Unit split | `[1,1,1,1]` | `{0,1}` / `{2,3}` | Neither `2/4` group finalizes |
| Exact threshold | `[2,1,1,2]` | `{0,1,2}` / `{3}` | Three keys with exactly `4/6` still cannot finalize |
| Below threshold | `[4,1,1,1]` | `{0}` / `{1,2,3}` | Neither the heavy `4/7` key nor the three `3/7` keys finalize |
| Byzantine bridge | `[2,2,2,2,3]` | `{0,1}` / `{2,3}`, faulty key 4 talks to both | Each side has at most `7/11`; neither finalizes |
| Unit positive control | `[1,1,1,1]` | `{0,1,2}` / `{3}` | The three-key `3/4` group finalizes A; the minority does not |
| Weighted positive control | `[3,2,1,1]` | `{0,1}` / `{2,3}` | The two-key `5/7` group finalizes A; the minority does not |
| Precommit cut, unit | `[1,1,1,1]` | `{0,1}` / `{2,3}` | All four emit real non-nil precommits; no recipient finalizes before healing |
| Precommit cut, exact threshold | `[2,1,1,2]` | `{0,1,2}` / `{3}` | Even three delivered non-nil precommits with `4/6` weight cannot finalize |

The four cold negative cases run rounds 0, 1, and 2. Honest scheduled proposers
author the valid value A; absent proposals close to nil. The Byzantine case has
two distinct valid values A and B with the same parent. Its actual first
proposer is key 4: it authorizes A for the first honest group and B for the
second, then equivocates its own prevotes and precommits across those groups.
Its `3/11` weight is strictly below one third. The overlapping support sets
`{0,1,4}` and `{2,3,4}` each count that key once; they are not disjoint network
components. Later proposal authorization still belongs to the actual scheduled
proposer. No honest private key is used to manufacture a message.

After each cold negative round, exact driver-issued Precommit due tickets
advance all four live nodes to the next Proposal phase without finality. After
R2, restored honest delivery in R3 finalizes A at all four original drivers.
The Byzantine key is silent after healing; honest `8/11` weight suffices in that
case. Cold cross-group envelopes are permanently dropped and counted; healing
does not restore them.

The precommit-cut cases remain in R0. Their held cross-group precommit envelopes
are released to their original recipients on healing, and all four drivers
finalize A. No certificate is assembled by the scheduler. The positive controls
stop after the prescribed majority reaches H2; they do not claim minority
recovery. These are finite progress controls, not proofs of eventual synchrony,
general healed-partition convergence, or production timeout policy.

## Driver and oracle integrity

`crates/naome-node/src/fixed_validator/tests/driver/partition.rs` routes only
complete canonical `PublishProposal` and `PublishVote` outputs from each honest
driver. Only the designated faulty fifth key uses raw signatures. Published
honest signer bytes are checked against their actor, and an honest vote intent
may appear only once per round and role in that execution. Every network copy,
including self-delivery, passes ordinary admission. Each proposal is separately
admitted to finality and voting, in that order.

The scheduler transfers all pending commands, including the arm command after
a vote publication, before admitting a wave. Phase barriers keep duplicated or
reversed ordinary evidence within its permitted admission phase. Due events
use the exact issued position, phase, and timer generation; the test selects no
wall-clock durations. Existing evidence remains in all four inboxes across
rounds, with a finite budget of 128 entries and 1 MiB per inbox. The scheduler
never drains them, and unexpected rejection, saturation, ambiguity, terminal
stop, or more than 4,000 driver steps fails the execution.

After every admitted event, driver step, and honest authoring action, the oracle
checks the selected head and height of every honest node. Every unfinalized
node's finality journal and finality anchor bytes must equal their initial
images. Vote/proposal safety files may advance normally. Every observed finality
must agree with other honest selections and have a recipient-local set of
actually delivered matching precommits satisfying independent small-integer
`3 * signer_weight > 2 * total_weight` arithmetic. Duplicate deliveries set an
existing signer bit and must also reach the driver's no-growth admission path.
There is no global pool of undelivered votes available to this oracle or driver.

These checks cover the sixteen specified executions and their scheduled
prefixes. They are deterministic local tests with real signatures and anchored
journal writes, not exhaustive message-queue model checking. They do not cover
arbitrary topologies, delay/reordering schedules, weights, Byzantine coalitions,
dynamic sets, extra heights, crashes, restart, storage faults, malformed payloads,
real sockets, separate processes, multi-region timing, or deployment. They do
not establish the general `SEC-007`, `SEC-008`, `SEC-013`, or production-readiness
requirements. The independent bounded model remains specified separately in
`specs/fixed-validator-safety-model-v0.md`.
