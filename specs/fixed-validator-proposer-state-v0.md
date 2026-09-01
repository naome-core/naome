# Fixed-validator proposer and branch state V0

## Status and authority

This specification defines the prerelease fixed-validator V0 proposer
accumulator, height-anchored round cursor, complete fixed-validator artifact-only
V0 branch-state projection, and immutable verified branch transition.

The public root constructor accepts exactly one caller-selected consensus
context, one caller-selected fixed validator key-and-weight set, and the exact
empty virtual-genesis snapshot for that context's artifact chain. This is an
explicit trust boundary: structural validation does not prove that the context,
genesis identity, or fixed set was selected by a canonical genesis ceremony.

After construction, callers cannot independently supply a later height,
consensus ancestry, artifact parent, active snapshot position, proposer,
priority vector, fixed-set identity, or expected state commitment. Later branch
states arise only from a complete envelope verified as one direct child of an
existing typed branch.

The branch result is intentionally immutable, memory-only, and branchable. It
does not by itself select a canonical sibling, install finality, resolve
conflicting certificates, mutate a journal, provide signing safety, execute
locking or timeout rules, change the validator set, fetch data, trust peers, or
execute economics. The separate fixed-validator finality journal is the sole V0
boundary that may consume a sealed verified transition and durably select and
replay its exact branch state.

## Fixed agreement set

The fixed set contains at most 256 entries. Every entry is:

```text
ConsensusKey[32] || AgreementWeight_u128_be[16]
```

Keys are sorted by their raw 32 bytes in ascending order. Duplicate keys,
zero-weight entries, and a total weight above `u128::MAX` are rejected. Input
order has no semantic effect. An empty set is representable as a zero-authority
halt state, but cannot produce a round cursor.

The trailing-NUL identity domain is:

```text
naome:fixed-agreement-set:v0\0
```

For entry count `n`, the exact identity is:

```text
FixedAgreementSetId = SHA256(
    fixed_set_domain
    || n_u16_be
    || sorted_entry_0
    || ...
    || sorted_entry_n_minus_1
)
```

## Canonical proposer priorities

One priority belongs to each sorted fixed-set entry. Priorities are exact signed
integers and their identity representation is a 32-byte signed two's-complement
big-endian integer. Values outside `[-2^255, 2^255 - 1]` fail closed. There is
no saturation, clipping, wrapping, floating-point arithmetic, or platform-sized
integer behavior.

The trailing-NUL priority-state identity domain is:

```text
naome:proposer-priority-state:v0\0
```

The exact state identity is:

```text
ProposerPriorityStateId = SHA256(
    proposer_state_domain
    || FixedAgreementSetId[32]
    || n_u16_be
    || priority_0_i256_be[32]
    || ...
    || priority_n_minus_1_i256_be[32]
)
```

The virtual-genesis priority vector is exactly `n` zeroes. There is no public
raw-priority constructor or decoder in V0.

## One proposer step

Let `W` be the fixed set's positive total weight and `p[i]` its current exact
priority vector. One step executes the following operations in order.

### 1. Rescale excessive spread

Let:

```text
D = max(p) - min(p)
```

If `D > 2W`, compute:

```text
q = ceil(D / (2W))
```

and replace each priority with exact signed division toward zero:

```text
p[i] = trunc_toward_zero(p[i] / q)
```

If `D <= 2W`, this phase changes nothing.

### 2. Center on the floor average

Compute:

```text
a = floor(sum(p) / n)
p[i] = p[i] - a
```

The floor rule is explicit for negative non-divisible sums and must not be
replaced with language-default truncation toward zero.

### 3. Add weight and select

Add every exact fixed weight:

```text
p[i] = p[i] + weight[i]
```

The entry with maximum resulting priority is the proposer. Equal priorities
select the lowest raw `ConsensusKey`. This raw-key rule is the NAOME V0 rule;
it must not be silently replaced by a derived-address ordering.

### 4. Subtract total weight

Subtract `W` from the selected entry only:

```text
p[selected] = p[selected] - W
```

The resulting vector must fit the canonical signed-i256 representation before
its identity is published. V0 exposes only a single-step proposer transition;
there is no public `advance_by(round_count)` operation or caller-supplied
random-access proposer state. A separate higher-round-certificate consumer may
repeat this exact step internally only after it has strictly inspected a bounded
certificate destination as specified below.

## Height anchoring and rounds

Let `B_h` be the proposer-priority base immediately before round zero of height
`h`.

```text
step(B_h) = (round_zero_proposer, B_h_plus_1)
```

That first step has two roles:

- it selects the proposer for `(h, 0)`; and
- its post-state is the sole base carried to height `h + 1` after a verified
  child transition.

Later rounds apply one additional proposer step at a time to a height-local
copy. They do not change `B_h_plus_1`:

```text
T_h_0 = B_h_plus_1
step(T_h_r) = (round_r_plus_1_proposer, T_h_r_plus_1)
```

Therefore a value verified at round zero or any later sequential round carries
the same next-height proposer base. Round, producer authorization, precommit
signatures, signer subset, and complete-envelope identity remain excluded from
the evidence-free value and branch-state commitment.

Height one derives only from the virtual-genesis branch. Every later cursor
uses exactly `verified_height + 1`; height and round overflow halt rather than
wrap. There is no random-access height or round constructor.

The lock kernel has one bounded phase-only higher-round path. Given its exact
current typed cursor at `(H, R)`, canonical generic quorum-certificate bytes,
and a positive caller-local inclusive maximum round `M`, it strictly inspects
only the certificate's exactly framed embedded position first. It requires the
same height and `R < P <= M` before any proposer step or signature work. It then
repeats the exact single-step transition internally from `R + 1` through `P`,
fully verifies the same certificate bytes against the private fixed-set snapshot at
the derived `(H, P)` cursor, and publishes no caller-selectable intermediate or
destination proposer state. Failure before or during derivation publishes no
cursor and changes no branch or lock state. The caller-local ceiling bounds
work; it does not change proposer or certificate validity.

## Fixed-validator artifact-only branch-state projection

The existing 32-byte `ConsensusStateCommitment` field is derived under the
trailing-NUL domain:

```text
naome:consensus-state-commitment:fixed-validator-artifact:v0\0
```

The exact preimage is 300 bytes:

| Offset | Width | Field |
| ---: | ---: | --- |
| 0 | 32 | exact `ArtifactChainId` |
| 32 | 32 | exact `ConsensusGenesisId` |
| 64 | 4 | `ConsensusProtocolVersion_u32_be` |
| 68 | 8 | positive direct-child `ConsensusHeight_u64_be` |
| 76 | 32 | exact parent `ConsensusAncestryId` |
| 108 | 128 | exact canonical child `ArtifactBlock` |
| 236 | 32 | exact `FixedAgreementSetId` |
| 268 | 32 | exact post-height `ProposerPriorityStateId` |

The commitment is:

```text
SHA256(state_commitment_domain || complete_preimage[300])
```

The preimage includes the parent ancestry, never the child ancestry. The child
ancestry hashes the complete value containing this commitment; including it in
its own preimage would create a self-referential hash cycle. The exact child
artifact block directly binds its artifact parent, previous set root, resulting
set root, and artifact identity.

Both state identities are derived from the same private post-height proposer
state. Callers cannot supply an inconsistent fixed-set/state pair. Strict value
decoding can still represent any observed 32-byte commitment, but the typed
branch verifier accepts only this internally derived digest.

## Typed branch transition

One `FixedConsensusBranchV0` couples:

- the exact consensus context;
- virtual genesis or the last verified positive height;
- the exact ancestry required by the next value;
- the immutable artifact snapshot required by the next artifact block; and
- the exact proposer base for the next height.

`begin_round_zero` derives the direct next height, exact active snapshot,
scheduled proposer, and post-height proposer base. `advance_round` consumes one
cursor and applies exactly one round-local step. The higher-round lock path can
derive multiple such steps only internally after its strict same-height,
strictly-higher, inclusive-work-limit preflight; callers still receive no
random-access round constructor or proposer-state fast-forward API.

For a cursor, `value_for_artifact_block` constructs the sole evidence-free
value fields and complete fixed-validator artifact-only V0 branch-state
projection for that candidate block. Complete envelope verification then:

1. enforces the bounded canonical envelope framing;
2. decodes the value;
3. checks exact branch context and direct child height;
4. checks exact parent consensus ancestry;
5. derives and checks the complete fixed-validator artifact-only V0 branch-state
   projection;
6. verifies producer authorization against the cursor's scheduled proposer and
   derived active snapshot;
7. verifies the non-nil strict-supermajority precommit certificate against the
   same snapshot and value root;
8. strictly validates the artifact block and payload against the branch's
   coupled artifact snapshot; and
9. publishes a separate immutable child containing the value ancestry, artifact
   successor, and once-advanced height proposer base.

Every envelope-verification failure leaves the branch, round cursor, artifact
journal, and selected state unchanged. Successful verification may be repeated
to construct explicit sibling candidates; it grants no preference or finality
between them. Only a synchronized fixed-validator finality-journal record may
publish one such child as the operable fixed-V0 head. Strict replay derives the
same height, ancestry, artifact snapshot, fixed set, and proposer base from the
retained envelope and payload; a durable conflict halt exposes no next-round
cursor or operable head. On a healthy halted journal only its terminal halt
summary and exact local journal-state identity remain diagnostic; branch,
record, length, parent, and commit access are denied.

## Resource and product boundary

The fixed set and signer bounds remain 256. Each cursor advancement performs a
fixed bounded number of passes over the fixed set with exact integer arithmetic.
Full envelope verification retains the existing 25,176-byte bound, verifies one
producer and at most 256 precommit signatures, and validates one artifact child.

This V0 completes a fixed-set, branch-relative proposer and transition kernel.
The separate fixed-validator proposal-control contract adds typed proposal
admission plus unsigned in-memory lock and valid-value effects without changing
this branch API's authority. The separate fixed-validator finality journal adds
exact-format durable selection, replay, and conflict halt. The separate
fixed-validator vote-safety journal can issue one private lock-state lineage,
bind each internally derived post-effect intent to a local key before signing,
require explicit acknowledgement of the exact externally durable prepare
identity, durably bind the completed vote before release, and recover only its
latest durable current-lineage state—either a completed vote or an anchored
higher-round checkpoint—through an exact typed round cursor. Its height handoff
consumes a matching owned verified transition and derives that transition's
child internally; this selects one local signing lineage but adds no global
sibling preference or durable-finality installation authority here. The lock
kernel and vote-safety journal additionally implement one bounded,
exact-certificate phase-only higher-round transition and its durable checkpoint
and restart boundary. They do not buffer or route proposals or certificates,
schedule timeouts, choose which observed certificate or branch wins, attest the
external anchor, or mutate finality. Dynamic validator selection and
transitions, finite-window proposer-gap proofs, timeout-driven progression,
node-runtime orchestration, general consensus persistence and recovery,
external-anchor storage, networking, peer trust, availability, and economics
remain separate required product work.
