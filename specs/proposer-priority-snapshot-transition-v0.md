# Proposer-priority snapshot transition V0

## Status and authority

This specification fixes the deterministic V0 priority transformation between
two complete active agreement snapshots. It consumes one internally reachable
proposer-priority state and one complete, caller-preselected replacement
[`ActiveAgreementSnapshot`]. The replacement snapshot has already enforced the
existing maximum count, distinct-key, positive-weight, and `u128::MAX` final
total-weight bounds.

The caller owns snapshot provenance and the decision to request this arithmetic.
Neither structural snapshot validation nor this transition proves canonical
validator eligibility, ranking, weight, ancestry, activation position, or
consensus adoption. The transition does not mutate a fixed-validator branch,
choose or sign a proposal, install finality, persist state, recover after a
restart, contact or trust a peer, execute economics, or prove any finite-window
or cross-snapshot liveness bound.

## Complete replacement input

The input is the complete final key-and-weight set, not an ordered list of add,
update, and remove operations. Entries have the canonical ascending raw
`ConsensusKey` order supplied by [`ActiveAgreementSnapshot`]. Its position is
not an arithmetic input and does not enter either state identity; changing only
that caller-supplied position cannot change the transition result.

Let the current sorted set and priority vector be `O` and `p_old`, and let the
complete sorted final set be `F`. A key is:

- retained when it occurs in both `O` and `F`, including when its weight differs;
- removed when it occurs only in `O`; and
- new when it occurs only in `F`.

No caller may supply a priority, pair a priority with another key, or construct
a state from raw priority bytes.

## Empty final set

When `F` is empty, the result is the existing typed empty agreement-set and
empty-priority halt state. The transition performs no total-weight division,
rescaling, centering, weight addition, or proposer selection. Calling the
ordinary proposer step on that state returns `NoActiveValidators`.

Producing this arithmetic halt state grants no authority to resume consensus
from it if a later caller supplies a nonempty snapshot.

## Nonempty transition

Let `W_final` be the positive total weight of `F`. First compute the exact
pre-removal updated total:

```text
U = W_final + sum(old_weight[k] for every removed key k)
```

This is equivalent to applying all additions and retained-key reweights before
removing old keys. `U` uses unbounded exact integer arithmetic because two
individually valid endpoint snapshots can make it exceed `u128::MAX`.

Construct one pre-normalization priority for every entry of `F`, in canonical
key order:

```text
if key k is retained:
    p_new[k] = p_old[k]

if key k is new:
    p_new[k] = -(U + floor(U / 8))
```

A retained key carries its exact old priority regardless of whether its weight
increases, decreases, or remains equal. A removed key and its priority do not
occur in the result. All new keys receive the same exact penalty.

Apply the existing `PROD-028` normalization exactly once to the complete
pre-normalization vector using `W_final`:

1. If the priority spread exceeds `2 * W_final`, divide every priority toward
   zero by `ceil(spread / (2 * W_final))`.
2. Subtract the floor average of the resulting vector from every priority.

The snapshot transition stops after normalization. It does not add weights,
select a proposer, or subtract total weight; those operations belong to the
next ordinary proposer step.

Every published result must fit the existing canonical signed-i256 priority
representation. Failure publishes no successor. The resulting
`FixedAgreementSetId` binds the complete final key-and-weight set, and the
resulting `ProposerPriorityStateId` binds that set identity and the complete
normalized priority vector under the existing domains. The source state is
immutable on both success and failure.

## Compatibility boundary

The fixed-validator artifact-only V0 branch continues to use one immutable set
for its complete lifetime. This transition kernel is deliberately separate
from that branch and supplies no canonical activation or integration path.
Existing fixed-set identity bytes, zero-state identity bytes, and proposer
schedules remain unchanged.

[`ActiveAgreementSnapshot`]: ../crates/naome-consensus/src/lib.rs
