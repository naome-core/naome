# Stable-slot proposer selection

`naome-consensus::proposer_selection` owns deterministic fixed-set arithmetic.
The canonical `StateBranch` feeds it four immutable slot identifiers with
weight one each. A slot retains its arithmetic identity when its owner and
period keys change. The selected parent snapshot resolves a selected slot to
its current consensus key; a vacant slot returns no proposer for that round.
Its turn is still consumed, and the four-slot quorum denominator is unchanged.
The general arithmetic accepts larger weighted sets for reference tests; the
state-v5 authority transition remains four equal slots. [Authority periods](authority-periods.md)
defines installation and [component ownership](ownership.md) maps its layers.

The hash domains below retain their literal `v0` spelling. They remain part of
the current arithmetic identity and are not permission to accept old history,
consensus messages, or signing journals.

## Fixed agreement set

The fixed set contains at most 256 entries. Every entry is:

```text
ConsensusKey[32] || AgreementWeight_u128_be[16]
```

Entries are sorted by their raw 32 bytes in ascending order. Duplicate keys,
zero-weight entries, and a total weight above `u128::MAX` are rejected. Input
order has no semantic effect. The reference arithmetic can represent an empty
set but cannot select a proposer from it. The canonical branch always supplies
four stable slot IDs through the same 32-byte arithmetic key type; these bytes
are not the rotating consensus public keys.

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
raw-priority constructor or decoder.

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
select the lowest raw arithmetic entry. For the canonical branch this means
the lowest stable slot ID, even when that slot is vacant; it must not be
replaced by a rotating consensus key or derived-address ordering.

### 4. Subtract total weight

Subtract `W` from the selected entry only:

```text
p[selected] = p[selected] - W
```

The resulting vector must fit the canonical signed-i256 representation before
its identity is published. The arithmetic exposes a single-step proposer
transition; there is no public `advance_by(round_count)` operation or caller-supplied
random-access proposer state. The canonical branch derives later rounds by
repeating this step under its configured maximum-round bound.

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
the same next-height proposer base. The round and signature set do not change
the next-height base or the evidence-free state value.

Height one derives only from the virtual-genesis branch. Every later branch
uses exactly `verified_height + 1`; height overflow fails rather than wraps.
`StateBranch::proposer(round, maximum_round)` rejects a round above the bound
before deriving its proposer from that branch's base.

## Canonical branch integration

`StateBranch::from_genesis` accepts only the height-zero `LedgerState` and
constructs zero priorities from its four stable slots. A later branch arises
only from verified agreement, READY and TERMINAL seals for a complete record
against the exact selected parent. `StateValue` binds genesis, profile,
outgoing authority ID, height, parent and child record identities, previous and
next ledger commitments, stable fixed-set identity, and next-height proposer
identity. The scheduled slot is derived from the branch and round, then
resolved under the selected parent snapshot. Callers cannot substitute a
priority vector or a current key for a vacant slot.

Agreement authenticates the scheduled proposal and a non-nil three-of-four
precommit quorum before full mathematical/state replay. It yields a provisional
`StateAgreement`, not a selectable successor. The exact agreed record and
successor snapshot need at least three incoming READY and three outgoing TERMINAL
signatures before `StateFinality` permits durable selection. The successor
carries the once-advanced height base, including when agreement arrived in a
later round. Key rotation does not reset those priorities. Storage owns
durable selection and conflict halt; proposer arithmetic alone supplies no
signing, selection, persistence, or network authority.

## Verification

[Arithmetic tests](../crates/naome-consensus/src/proposer_selection/tests.rs)
cover exact identities, priority normalization and ordering.
[Weighted reference tests](../crates/naome-consensus/src/weight_oracle.rs)
cover full-width arithmetic and threshold classes.
[Canonical consensus tests](../crates/naome-consensus/src/state/tests.rs)
exercise branch-relative slot selection, vacancy, rotation, and sealed
finality. These bounded tests are not qualification of physical multi-machine
handoff or a weighted validator network.
