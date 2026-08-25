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

The result is intentionally immutable, memory-only, and branchable. It does not
select a canonical sibling, install finality, resolve conflicting certificates,
mutate a journal, persist or recover state, provide signing safety, execute
locking or timeout rules, change the validator set, fetch data, trust peers, or
execute economics.

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
its identity is published. V0 exposes only a single-step transition; there is
no `advance_by(round_count)` operation and no input-sized fast-forward loop.

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
cursor and applies exactly one round-local step.

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
between them.

## Resource and product boundary

The fixed set and signer bounds remain 256. Each cursor advancement performs a
fixed bounded number of passes over the fixed set with exact integer arithmetic.
Full envelope verification retains the existing 25,176-byte bound, verifies one
producer and at most 256 precommit signatures, and validates one artifact child.

This V0 completes a fixed-set, branch-relative proposer and transition kernel.
Dynamic validator selection and transitions, finite-window proposer-gap proofs,
Tendermint locking and valid-value state, anti-equivocation signing state,
canonical branch selection, conflicting-certificate halt, durable atomic
finality, persistence, restart recovery, networking, peer trust, availability,
and economics remain separate required product work.
