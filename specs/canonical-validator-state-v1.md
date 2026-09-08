# Canonical validator-state foundation V1

## Status and applicability

This is a draft protocol contract for the canonical account and validator-state
foundation. It records selected semantics and identifies the byte-level,
resource, economic, and integration requirements that remain unspecified.
Selected decisions are mirrored in `consensus-rules.md`; remaining decisions
retain explicit open entries there. This is not an implemented consensus
profile, a production genesis, or evidence
that an incomplete rule in `consensus-rules.md` is implemented.

V1 names the successor schema family in this document. Its exact protocol-version
commitment, domain strings, complete encodings, and admission limits remain to
be specified before consensus-facing implementation. The current fixed-validator
artifact-only V0 profile remains a separate format.

The foundation supports permissionless account and validator-registration
admission under authenticated state transitions. Registration alone grants no
active membership, proposer authority, consensus-signing authority, finality,
branch selection, or canonical-state installation authority.

## Consensus framing and commitments

The successor uses explicitly versioned strict binary framing. It has new value,
signing, ancestry, and envelope domains and a strict decoder. It does not append
to or reinterpret V0 bytes. The existing 128-byte `ArtifactBlock`, its identity,
the artifact-chain definition, and their existing domains remain unchanged.

The successor proposal value binds its exact context, finalized-height
coordinate, parent consensus ancestry, artifact block, post-artifact-state
commitment, post-consensus-state commitment, prior-height settlement input,
operation sequence, and applicable definition supporting-proof input. Exact
field framing remains unfinished.

At height greater than one, the settlement input is the exact canonical valid
precommit certificate for the preceding height. The first non-genesis height
uses the separately specified genesis-commit sentinel. A different valid
prior-height settlement certificate produces a different next-height proposal
signing root and consensus ancestry.

Current-height producer authorization and agreement evidence are excluded from
the proposal signing root and proposal post-state. The final envelope identity
includes that evidence. Valid current-height evidence variants for one proposal
therefore share its proposal root and ancestry but may have different envelope
identities. `CODEC-046` and `CODEC-047` record this current-height distinction;
prior-height settlement evidence is committed execution input.

No state field may introduce a self-reference through the resulting proposal
root, child ancestry, or final envelope identity. Parent-state verification and
transition execution precede deriving those child identities.

## Typed authenticated state

The consensus-state commitment contains a fixed ordered set of typed subroots.
Each subroot commits a distinct state namespace through a SHA-256 compressed
binary Patricia map. The complete namespace inventory and its fixed ordering
remain to be specified. The inventory must cover every consensus-relevant
account, validator, escrow, delegation, scheduled-change, snapshot, reward,
attribution, liability, penalty, and accounting fact used by a transition.

Every map leaf binds its canonical logical key and canonical value. Empty, leaf,
branch, and aggregate-root hashing use separately specified versioned domains,
including the applicable namespace. Routing uses a 256-bit domain-separated
hash of the canonical logical key. A branch records the first differing bit
from the most-significant end and its ordered left and right child commitments.

Canonical paths have strictly increasing branch-bit positions and correct
left/right routing. Branches have two nonempty children. Deletion collapses
unary structure. Equivalent key/value maps have the same root regardless of
insertion or deletion history. At most 256 branch positions occur on a path;
this structural bound is not a performance measurement or a proof wire format.

Stored records retain the canonical logical key. Before replacement, unequal
logical keys with the same routing digest are rejected rather than aliased.
Loading and replay recompute routing and enforce the same rule. Hashes remain
computational commitments under their cryptographic assumptions.

The current artifact-set commitment remains unchanged. Its leaves commit
artifact IDs, so it cannot be reused unchanged as an account or validator-value
commitment.

Matching supplied state or witnesses to an expected root establishes only that
relationship. The boundary that supplies the root must separately establish its
canonical-parent provenance. An uninstalled transition cannot establish that
provenance for itself, and installation must recheck the parent to which the
transition is bound.

### Semantic coverage inventory

The complete namespace inventory must cover the following facts, either as
committed records or through a specified authenticated derivation with retention
and bounded-work obligations. This list does not select subroot ordering, record
layout, or unfinished economic semantics.

| Semantic family | Required coverage | Ledger basis |
| --- | --- | --- |
| Accounts | Creation identity, policy, nonce, liquid balance, recovery policy and pending changes | `ECON-003`, `ECON-004`, `ECON-027`, `ECON-142`, `ECON-156`–`ECON-162` |
| Registrations and keys | Stable lineage and roles, registration order, current and historical keys, pending activation, permanent reservations | `PROD-005`, `PROD-010`, `PROD-047`, `PROD-088`, `ECON-106`, `ECON-143`, `ECON-144` |
| Bond custody and exposure | Beneficiary principal, backing, reductions and exits, retained liable portions, release eligibility | `ECON-096`–`ECON-110`, `PROD-006` |
| Attribution | Commitments, payer/beneficiary, deposits, deadlines, replay facts, winning attribution and supporting proof | `ECON-028`, `ECON-060`–`ECON-079`, `ECON-113`–`ECON-118`, `ECON-131`–`ECON-134` |
| Ordinary Knowledge Weight | Origin batches, ownership, activation, original amount, decay, penalties and cumulative first-matured weight | `ECON-039`–`ECON-045`, `ECON-049`, `ECON-052`, `ECON-059`, `ECON-111`, `ECON-112`, `GOV-039` |
| Delegation and commission | Owner authorization, requested/effective allocations, activation, commission history, reward checkpoints and separate grant delegation | `ECON-085`–`ECON-095`, `ECON-120`, `ECON-121`, `ECON-123`, `ECON-141`, `ECON-154`, `ECON-155` |
| Consensus snapshots | Immutable eligible/active weights, keys and lineage, historical delegation/commission, proposer priorities and settled participation | `PROD-024`, `PROD-028`, `PROD-029`, `PROD-035`, `PROD-039`–`PROD-044`, `ECON-109`, `ECON-137`, `ECON-140`, `ECON-145` |
| Fee reward custody | Unsettled height pools, accumulator obligations, carries and claim checkpoints | `ECON-081`–`ECON-085`, `ECON-120`, `ECON-137`–`ECON-139`, `ECON-152`–`ECON-155` |
| Penalties and scheduling | First-penalty marker, offense replay classification and snapshot, queued changes, required deadline reservations | `ECON-015`, `ECON-106`, `ECON-145`, `ECON-174`, `ECON-179`–`ECON-181`, `PROD-039`–`PROD-042` |
| Reserves and governance | Bootstrap reduction, development vesting, grant treasury/delegation/snapshots/votes/execution/rolling spending, upgrades and cancellation | `GOV-021`–`GOV-055`, `GOV-084`, `GOV-087`, `GOV-006`, `GOV-007`, `GOV-104`–`GOV-106` |
| Supply and tail | Ownership of every live atom, issuance and burn accounting, eventual tail-event destinations and realization state | `ECON-005`–`ECON-007`, `ECON-193`–`ECON-205`, `ECON-211`, `ECON-212`, `ECON-222` |

Citation NAO rewards are immediately spendable; the E+2 delay applies to their
derived Knowledge Weight, not a citation-money escrow (`ECON-040`, `ECON-056`).
Fee reward entitlements remain nonspendable until claimed (`ECON-085`, `ECON-138`).
Reclassifying pool backing as reward obligations must not count the same atoms
twice. Historical bond exposure references principal without duplicating it;
historical delegation references weight origins without minting more weight.
Attribution deposit refunds belong to the payer, whereas released bond principal
belongs to its immutable beneficiary.

Tail realization and machinery reuse remain open under `ECON-222` and
`ECON-205`. Empty reserved namespaces cannot resolve those choices. Recovery
activation, exact accumulator/carry arithmetic, delegation rounding, liability
ordering and deadline accounting retain their unfinished contracts. Grant-vote
authority, consensus delegation and development-reserve spending remain distinct.

## Stable account and registration identities

An account ID derives from a domain-separated hash of its immutable creation
descriptor: its initial canonical authorization policy and an explicit 32-byte
creation discriminator. Exact descriptor and preimage bytes remain unfinished.
The initial descriptor remains immutable; current account authorization policy
is separate state. Key rotation preserves account identity, ownership of
balances and Knowledge Weight, registration references, and historical
liabilities. Explicitly authorized fees and independently scheduled state
effects remain applicable; rotation does not transfer or recreate ownership.

Account creation is explicit. Ordinary credits and registration role references
must resolve to existing accounts; a credit does not invent authorization policy.
Post-genesis creation requires initial-policy consent and an existing sponsor's
authorization over the complete creation operation. The sponsor pays its fee and
any initial funding from authenticated available funds.

The new account authorizes creation with nonce zero. Successful creation consumes
that nonce and leaves its next nonce at one. The sponsor consumes its own exact
current nonce once. Rejection creates no account, credits no initial funding,
charges no fee, and consumes neither nonce.

A registration ID derives from a domain-separated hash of the stable operator
account ID and the operator nonce consumed by that registration. It does not
derive from the current consensus key, authorization evidence, or signature
subset. Consensus-key rotation preserves the registration and liability lineage.

These identifiers belong to their containing genesis state. Their derivation
does not depend on the final genesis identity. Ordinary operation authorization
still binds the full chain, genesis, protocol-version, and operation-role
context. Exact identifier domains and integer encodings remain unfinished.

### Bond reduction and liability refinement

The selected refinement of `ECON-109` tracks the liability window of each amount
removed from effective backing, rather than requiring the entire registration to
exit before any excess principal can mature. `ECON-100` and `ECON-109` record
this selected refinement and remain unimplemented.

An exit or bond reduction finalized in epoch E is excluded throughout E and E+1
and first eligible in E+2. This explicitly extends the increase-delay convention
of `PROD-009` to these requests. Eligibility is not guaranteed execution: the
actual effective transition must still obey the voluntary churn rules. Merely
submitting or finalizing a request does not remove principal from backing or
start its release clock.

When a reduction actually becomes effective, its exact amount stops backing
agreement weight and remains escrowed as liable principal. Let L be that amount's
last effective exposure epoch. It remains liable throughout the 30 complete
epochs L+1 through L+30; it can become released principal no earlier than the
first height of L+31. This permits an excess reduction to mature while other
principal continues backing an active registration. Current backing, retained
reduction amounts and released principal are disjoint accounting categories;
exposure records do not duplicate their atoms. Equal exposure/release conditions
may share one record if this preserves every liability and accounting fact.

While a registration remains eligible, including during a partial exit, its
currently usable backing must be at least
`max(10^13, ceil(w / 20))` NAO atoms for effective weight w. The `10^13` atoms
are exactly 10,000 NAO under `ECON-002`; the second term follows from the
20-weight-units-per-atom cap. The minimum remains in force until full effective
exit. This lower bound does not automatically schedule or release excess bond.

A bond top-up becomes liable when its acceptance finalizes, including while
waiting for activation. Its additional usable backing and weight capacity become
effective only through the delayed, churn-compliant activation transition.
Pending top-up principal is therefore distinct from currently usable backing
and from released principal, without counting its atoms twice.

For a registration that has never had effective active exposure, an effective
exit that cancels its pending activation may release its bond without an additional
30-epoch wait. The E+2 exit eligibility delay still applies. This exception applies
to a never-exposed registration, not to a new deposit into a previously exposed
lineage, and does not erase another existing liability obligation.

The first canonically executed valid equivocation penalty forfeits all currently
liable principal in the registration lineage, including liable top-ups added
after the proven offense. It is not restricted to principal present at that
offense position. The selected set does not include principal already validly
released from liability. The one-transition marker, permanent lineage tombstone,
and 90% burn/10% reporter split retain their existing requirements.

Withdrawal requires the immutable beneficiary's authorization, debits only
released principal and credits that beneficiary. Cancellation, re-bonding or
new deposits cannot erase an existing exposure obligation.

Economic penalty eligibility and the corresponding historical delegation-snapshot
liability expire at the end of offense epoch E+30. Rotation, inactivity, re-entry
and later activity do not extend or reopen that offense deadline. This is a
separate explicit refinement of `ECON-109`: an offense's deadline does not derive
from the newest bond tranche or the lineage's latest active epoch. When eligible
evidence executes, the selected forfeiture set is still all principal currently
liable at execution, rather than the principal present at the offense.

The same canonical-execution deadline governs all equivocation-evidence
admission under `ECON-247`. Even otherwise valid, distinct non-penalizing
evidence against an already penalized lineage under `ECON-188` is rejected
after the final height of its offense epoch E+30. Before that deadline it
remains subject to the bounded pending-evidence rules and creates no second
destructive penalty or reporter reward.

Evidence must execute canonically by the final height of its deadline epoch
to be admitted.
Local receipt, partial acquisition or mempool presence creates no bond hold.
Matured bond amounts release at the following epoch boundary before ordinary
operations. An earlier withdrawal within the ordinary operation stream cannot
change those eligibility and release results. This deliberately allows evidence
that has missed its canonical execution deadline to lose penalty eligibility;
it does not promise inclusion merely because an honest node received evidence.
The independent deadline-reservation and honest-proposer-gap requirements remain
unfinished under `ECON-181`, `RES-049` and `PROD-091`.

Exact handling of re-bonding, churn queue integration and conflicting requests,
rounding, and ordering of release relative to settlement and other epoch-boundary
effects remain unfinished. The selected deadline and release rules do not alone
establish the complete evidence-admission or epoch-transition contract.

### Exit precedence and re-bonding

A finalized exit is irreversible for that registration. Neither the operator nor
the beneficiary can cancel it, restart its delay or move its queue position
backward. Other pending requests cannot prevent either role from initiating exit.
Future participation after that exit requires a fresh registration and an unused
consensus key, with the independent bond and authorization requirements; it does
not erase the former registration's liability or tombstone history.

Exit takes precedence over unapplied backing and weight increases. Finalizing
exit cancels their future activation, and later increase requests are rejected.
Canceling activation does not refund principal or remove its liability. The
already effective state changes only through the delayed transition and its
remaining churn budget. Canceled pending top-ups and pending re-bonds remain held until full effective
exit. For a previously exposed registration, these amounts remain liable through
30 complete epochs after its last effective active epoch, preserving any later
pre-existing release floor. An amount with no previous release floor uses the
exit-derived floor alone. The never-exposed-registration exception remains
applicable only without erasing an existing exposure obligation. Independent
cooling reductions retain their own release clocks and are not re-locked by this
rule. Release also requires completion of the effective exit and the applicable
boundary release phase; canceling activation creates no spendable duplicate.

A repeated exit request for an already-exiting registration is rejected. It
changes no fee, nonce, queue position, effective date or other state.

An explicitly beneficiary-authorized direct re-bonding operation moves retained
principal into a disjoint pending-rebond category. It preserves the amount's
existing release floor and holds the principal liable while awaiting delayed,
churn-compliant activation, even when that old release date arrives first. The
same principal is not simultaneously withdrawable or usable backing elsewhere.
While it later backs active weight, no old release date makes it withdrawable.
On subsequent effective reduction or exit, its release floor must preserve both
the old obligation and the new complete exposure window.

Partial re-bonding splits amounts without duplicating atoms. Records may merge
only when their remaining rights and conditions are identical. V1 provides no standalone pending re-bond cancellation operation. The amount
proceeds through activation and subsequent ordinary reduction or exit, or follows
the irreversible-exit cancellation and retention rules above. Canceling a
re-bond intent cannot independently unlock the principal.

### Voluntary churn refinement

For an epoch following a completed non-genesis epoch, W is the total agreement
weight in the authorization snapshot of that preceding epoch's final height.
Penalties executed by that final height do not change this historical reference.
Genesis initialization of the reference remains part of the genesis contract.
For positive W, the selected integer voluntary churn budget is `ceil(W / 10)`. This explicitly refines `PROD-039`:
the budget may exceed exact 10% by less than one indivisible weight unit. A
floor-rounded budget would permit zero progress at totals one through nine.
Zero total eligible active weight retains `PROD-034`'s halt without fallback
weight, quorum relaxation or bootstrap extension. The refinement does not grant
recovery authority or prove eventual execution of every queued change.

Churn counts both increases and decreases in effective active agreement weight
by stable validator registration: moving one unit from A to B costs two units.
A pure key rotation preserving the registration-weight mapping costs zero.
Penalties, Knowledge Weight decay and terminal bootstrap sunset retain their
mandatory treatment outside voluntary delay under `PROD-041`. Growth-driven
bootstrap replacement and the independent bootstrap cap retain `PROD-042`.
The mandatory comparison state applies the due penalties, decay and independent
bootstrap-cap reductions, then reranks already-effective eligible candidates.
Promotions caused by that mandatory reranking belong to this comparison state;
they do not newly activate requested capacity. Newly activated capacity remains
in the voluntary queue. Thus mandatory removals change the comparison state
without changing the selected historical denominator. Exact composition of
queued requests must still prevent a net-total-only calculation from hiding
replacement of one registration's weight by another's.

Ordinary Knowledge Weight matures on its required schedule and advances the
first-matured accumulator independently of active-set staging. Maturation makes
owner capacity available; any resulting increase in effective consensus weight
remains subject to staged churn. This explicitly distinguishes matured owner
weight from activated voting weight in `ECON-040`. Exact delegation-growth
event identities and exact eligibility coordinates remain to be specified;
the standing authorization and fresh-priority rule below apply. The first-matured
accumulator still determines the growth-driven bootstrap target; that replacement
retains its queue treatment while the independent linear cap is not delayed.

Eligible requests are ordered by eligibility epoch, finalized request height,
committed operation position and operation ID. An unfinished portion retains its
original position, takes the maximum canonical progress permitted by the
remaining budget, and leaves later requests to the remaining budget. This is the
selected ordering for the draft, not evidence that `PROD-040` is implemented.

Requested delegation and bond-backed capacity are separate from currently
effective consensus weight. Eligible changes activate in partial increments;
top-256 ranking uses the resulting effective weights. Unapplied weight retains
its ownership but grants no active consensus authority. This selected separation
does not authorize counting one owned unit in multiple effective allocations.

Exact staged eligibility, coupled transfers, conflicting requests, cancellation
and supersession remain unfinished. Partial economic changes must preserve
integer bond backing and Knowledge Weight ownership; a permitted weight delta
alone does not determine the exact bond atoms that cease exposure. A partial
transition must account for the complete selected registration-weight change,
including a displaced incumbent, rather than charging only the changed candidate.
Rounding and partial remainders must be specified with these transitions before
`PROD-066` can be completed. These rules do not authorize arbitrary reduction of
an incumbent's weight merely to make a newcomer fit.

## Account authorization and operation identity

An account policy has one normalized representation: a threshold `M` and sorted,
distinct Ed25519 keys, with `1 <= M <= N`. A single-key account is the `M = N = 1`
case. Exact policy bytes, key-admission checks, and the benchmark-selected maximum
`N` remain unfinished.

Each authorization contains exactly `M` distinct signer entries in ascending
policy-index order. Every supplied signature is verified. Duplicate indices,
unknown indices, extra signatures, and malformed evidence fail. Any qualifying
`M`-key subset is acceptable; there is no requirement to use the globally lowest
`M` keys. Different qualifying subsets can produce different valid evidence.

Every required account authorizes the complete common operation, including its
context, all role assignments, and the full distinct-account nonce vector.
One account occupying several authorizing or paying roles authorizes all those
roles and consumes one nonce. Different authorizing accounts each supply and
consume their own exact nonce. A receiving-only reward account supplies neither
an authorization nor a nonce for registration.

Operation identity and signing intent exclude signature evidence. All identity
and possession-proof targets are derived before the signatures that authorize
them, without a signature/identity cycle. The exact operation, policy-binding,
account-specific authorization, and proof-of-possession transcripts remain to
be specified. Validation uses the applicable evolving execution state; signing
does not require committing an intermediate global state root.

## Bonded validator registration

Registration binds distinct operator-authorization, consensus-signing,
reward-receipt, and bond-escrow roles. The operator, fee payer, bond beneficiary,
and reward recipient accounts may coincide or differ. Every authorizing or
debited account signs the complete operation under the nonce rule above.

The new consensus key separately proves possession over the complete operation
and context. That proof grants no account-spending authority. Registration
atomically applies fee payment, actual bond debit and escrow, nonce consumption,
the registration record, and consensus-key reservation, or changes none of them.

The bond funder is its immutable beneficiary. Released principal is credited only
to that account. This foundation does not introduce gifted bonds, transferable
bond claims, or multiple funding shares within one registration.

The existing minimum is 10,000 NAO. Each escrowed atom supports at most 20 units
of effective agreement weight. Registration records do not themselves establish
delegated weight, active-set selection, or consensus authority.

Successful registration or rotation admission permanently reserves its consensus
key within the containing genesis context. An already admitted key cannot be
assigned again, including to another registration or by reactivating a retired
key. Invalid admission reserves nothing. Historical key assignments and lineage
tombstones remain available for the required verification and liability rules.
Cancellation outside the explicitly selected exit-precedence behavior requires
its own exact contract before support.

Either the operator or the bond beneficiary may request delayed exit. The
beneficiary may request bond reduction and may withdraw only released principal
under the selected backing and liability rules. The operator's consent at
registration includes these beneficiary rights.

A request is distinct from an effective change and from withdrawable value.
Exit or reduction does not shorten offense liability. The existing
30-complete-epoch liability window, complete offense-liable forfeiture, and
lineage-wide permanent tombstone rules remain binding. The refinements above
select exposure and deadline semantics; exact record bytes, remaining scheduling
and epoch-boundary integration are unfinished. These rights do not imply that
the operations are implemented.

## Delegation targets and integer allocation

A consensus delegation request specifies an absolute maximum number of Knowledge
Weight units for each target registration, not a relative share of all future
owner capacity. These requests do not transfer ownership. Requested amounts,
computed allocation targets and currently effective allocations are distinct.
Target calculation alone grants no active consensus authority.

Let L be the owner's applicable live Knowledge Weight, let r_i be its requested
nonnegative amount for target i, and let R be the exact sum of the requests.
If R is zero, every target allocation is zero. If R is at most L, the targets
are exactly r_i and L-R remains undelegated. Otherwise, use the selected
highest-averages allocation:

1. Initialize each target to `a_i = floor(L * r_i / R)`.
2. While fewer than L units have been assigned, increment the target maximizing
   `r_i / (a_i + 1)`, recomputing its quotient after each increment.
3. Compare quotients exactly by cross multiplication; floating-point or rounded
   division is not permitted. Equal quotients are ordered by ascending
   `RegistrationId`, compared lexicographically by their canonical identifier
   bytes. This order is independent of L and of request arrival order.

L=0 yields all zero allocations without evaluating an R/L threshold. The number
of increments after initialization is less than the number of targets, because
it equals the sum of the fractional parts discarded by the initial floors.
Resource bounds must nevertheless account for target count, operand lengths,
exact products and maximum selection; this mathematical bound is not a selected
operation limit or a measured complete-operation cost.

For fixed requests and fixed tie order in the oversubscribed case `0 < L < R`,
this procedure is equivalent to selecting the first L quotients from the
sequences `r_i/1, r_i/2, ...`. The seeded
quotients are exactly those at least R/L, and their count is at most L. Completing
that prefix by successive maxima therefore produces the same global prefix.
Consequently increasing only L cannot reduce any target allocation. At L=R,
the targets equal the requests, so a target never exceeds its absolute request
in the oversubscribed case; for L>R, allocations remain at the requests and
surplus capacity is undelegated. This guarantee does not cover changed requests,
changed eligibility, bond caps, or staged effective allocations.

Highest averages deliberately permits violations of rounded proportional quotas.
For requests `(1,1,5)` and L=4, it produces `(0,0,4)`, even though the largest
request's exact proportional share is 20/7 and its ceiling is three. The choice
refines the remainder contract under `ECON-093` and `ECON-126`; it must not be
described as quota-preserving largest-remainder allocation.

An existing absolute request provides standing owner authorization for newly
matured capacity up to its requested maximum. No fresh signed request is required
solely because that capacity matures. A newly available amount receives fresh
queue priority at its canonical availability event; it does not inherit the
original request age. Unchanged pending portions retain their existing priority.
The original request eligibility and weight maturity must both be satisfied.
Once both conditions hold, the newly matured amount may participate in churn
without another E+2 wait. The exact derived-event identity and total queue
ordering remain unspecified. Automatic queuing grants no immediate active
weight and remains subject to staged churn.

For maturation-derived growth, the chronological queue comparison uses the
canonical finalized-state availability coordinate in place of an ordinary
request's finalized-operation coordinate. An automatic event is not a signed
ordinary operation and must not manufacture an operation position or reuse an
ordinary operation identity. The common ordering still starts with eligibility
and age: a separate event-kind-first pass must not put newly available growth
ahead of older eligible requests.

Simultaneous maturation effects for an owner are aggregated before computing its
new allocation targets, so origin-batch enumeration cannot choose which target
receives a rounding unit or earlier priority. Derive at most one new increment
per owner and registration at that coordinate. Their total ordering must be
independent of input arrival or origin-batch enumeration; its exact simultaneous-
event tie rule remains to be specified. Previously queued unchanged portions remain distinct
with their retained priority; aggregation must not renew or backdate them.

The exact event encoding and coordinate derivation must still cover interaction
with mandatory decay, penalties, target eligibility and concurrent amendments.
These ordering constraints neither complete that integration nor grant earlier
activation than the original request eligibility and capacity maturity.

### Delegation-plan amendments

An authenticated owner amendment preserves unchanged amounts and their existing
pending priority. Additional requested amounts receive the amendment's fresh
priority and ordinary E+2 eligibility. A finalized decrease immediately cancels
its excess unactivated portions, newest pending portions first. Those canceled
portions cannot activate during the amendment's delay or be restored through the
superseded standing request. The surviving unchanged pending portions retain
their original priority.

Already effective amounts are not removed at amendment finalization. Their
voluntary reduction is excluded throughout the finalization epoch E and E+1,
first becomes eligible in E+2, and still requires available churn budget. A
transfer to another target may activate only when the owned capacity is actually
available; the old and new targets cannot count the same unit simultaneously.
Cancellation of an unactivated intent alone changes no effective active weight.
Mandatory decay and penalties retain their separate, undelayed treatment.

A later authenticated amendment may immediately reduce an earlier unapplied
reduction of weight that is still effective. The surviving unchanged reduction
portions retain their existing eligibility and queue priority. This cancellation
preserves existing effective weight, spends no churn, and does not impose a new
E+2 delay merely to retain that weight. The additional-amount E+2 rule applies
to fresh activation, not to this retention of already-effective weight.

For example, effective weight 100 followed by requested targets 60 and then 90,
with no reduction yet applied, leaves a pending reduction of 10 under its
existing eligibility and priority. If the first reduction already brought the
effective weight to 80, changing the target to 90 cancels the remaining old
reduction and requires a fresh increase of 10 under the later amendment's E+2
eligibility and churn budget. Previously removed weight is not restored by
canceling a pending reduction. Previously canceled unactivated portions do not
recover their old activation authority or priority. Irreversible registration
exit retains its separate precedence and cannot be canceled by a delegation
amendment.

When several reduction portions for the same owner and target are pending,
cancel newest portions first, in reverse of their canonical queue order. For
remaining cancellation amount C and the current portion amount Q, cancel
`min(C, Q)` and continue toward older portions only if C remains positive.
A partially canceled portion keeps its original eligibility and priority for
its surviving amount. This procedure neither changes already executed effects
nor renews the age of any survivor.

An amendment is evaluated against the owner's complete requested target vector.
Every additional activation caused by that amendment receives its fresh priority
and E+2 eligibility, even if the receiving target's own absolute request field
is unchanged. For live capacity 100 and requests `(100,100)`, targets are
`(50,50)`. Amending the first request to zero produces targets `(0,100)`; the
second target's additional 50 units follow the amendment's delay and cannot
activate before capacity is actually available. Existing unchanged pending
portions retain their old priority. This is not maturation-derived growth and
does not use its no-second-wait exception. Retention of already-effective weight
through cancellation of a pending reduction retains its separate rule above.

Canonical request encoding, integration with simultaneous capacity and target-
eligibility changes, and origin-batch assignment remain unfinished. Historical offense-snapshot
obligations and fee-reward checkpoints require their own exact contracts. Computing aggregate targets does not settle `ECON-105`, `ECON-146`
or `ECON-155`, and staging must never count one owned unit in two simultaneous
effective allocations.

## Ordered transactional execution

The proposal commits one ordered operation stream with economic and validator
type tags. Its two class subsequences retain separate count and byte bounds.
Ordinary operations retain their committed positions, permitting account
creation or funding before a later operation that consumes the result.

The included deadline-bearing subsequence must be ordered globally by earliest
consensus deadline and then ascending operation ID. A violation invalidates the
block. This is an explicit block-validity requirement beyond the honest-proposer
wording of `SEC-036`. It constrains included operations; it does not prove that
every operation available in a remote mempool was included.

Before reading a height H proposal's execution inputs, derive H's authorization
snapshot from the authenticated finalized parent state and deterministic height
and epoch rules. Boundary preparation is a pure parent-derived view, not an
installation of speculative canonical state. Effects whose selected effective
coordinate is H must be reflected in this view before authorizing H, including
terminal bootstrap sunset at the first height of epoch 730. Exact internal
ordering among the remaining boundary effects still requires specification.

The resulting participant snapshot is fixed for H's rounds. A prior-height
certificate variant selected inside H's proposal cannot choose H's membership,
weights or quorum denominator. A penalty finalized at H does not change H's
snapshot; its mandatory consequences affect the next height's snapshot, including
when H+1 is in the same epoch. Historical certificate verification retains its
own exact snapshot.

Prior-height settlement is the first proposal-dependent execution phase, using
the corresponding historical weight, delegation and commission data; the first
height uses its genesis sentinel. The approved boundary-release phase precedes
ordinary operations. The committed operation stream follows, and artifact
publication runs last. Same-block delegation, registration or rewards cannot
retroactively authorize the block or alter prior-height settlement inputs.

Prepared boundary effects and proposal-dependent effects form one atomic
transition. Neither the preliminary view nor a rejected proposal installs a
canonical state update. Settlement-first execution does not permit a proposal's
selected settlement input to authorize that same proposal. Exact ordering of
boundary accounting relative to settlement remains to be completed while
preserving this authority separation.

Repeated unsigned operation IDs are rejected across both classes, including
different authorization variants of one operation. Reuse of an authorizing
`(AccountId, nonce)` pair across operations is rejected. Within one operation,
repeated account roles share one nonce. Different operations may consume
successive nonces, checked against evolving execution state. Duplicate account
creation targets and already reserved consensus keys fail their state checks.
Repeated lineage references alone are not duplicates: later distinct evidence
must preserve the already-selected no-second-penalty behavior.

Every operation must have sufficient funds at its execution point. It cannot
borrow from later effects. Every speculative effect belongs to one transactional
overlay. A rejected proposal installs no fee, nonce, balance, escrow,
registration, attribution, or artifact change.

A payer-authorized reveal that violates its committed claim has the selected
valid deposit-forfeiture outcome under `ECON-116`. This is not a rejected
operation that mutates state. Unauthorized or malformed reveal attempts retain
the no-write rule of `ECON-134`; a beneficiary-only claim-violating reveal retains
the no-mutation rule of `ECON-171` and does not acquire the payer's forfeiture
authority. A reveal requires a commitment from a strict ancestor, although a
valid reveal may precede its artifact in the same block.

Exact epoch-boundary, expiry, penalty, exposure, account-policy activation, and
tail-settlement rules remain unfinished. The ordering above does not supply
those missing transitions or complete `CODEC-068` by itself.

## Exact integers and resource admission

Heights, account nonces, and accounting quantities use exact growing integer
domains, with exact signed integers where required by proposer priorities and
their arithmetic. Reference `u64`, `u128`, or fixed signed widths do not establish
protocol limits.

An unsigned natural is encoded as its magnitude's byte count in minimal ULEB128,
followed by that many minimal big-endian magnitude bytes. Zero has an empty
magnitude and is encoded as the single byte `00`. A positive magnitude has no
leading zero byte. The byte count has no fixed protocol integer width; its
admissible prefix length is derived from the applicable magnitude bound.

In a ULEB128 byte-count prefix, each byte contributes its low seven bits in
least-significant-group order. The high bit is set exactly when another prefix
byte follows. Zero is one zero byte; a multiple-byte prefix cannot end in a
zero low-seven-bit group. Unterminated, oversized, or nonminimal prefixes fail
before allocating the magnitude.

A signed integer has a sign byte followed by that unsigned magnitude encoding:
`00` means nonnegative and `01` means negative. Other sign bytes and negative
zero are invalid. These sign tags are part of this draft's exact wire contract.

| Integer | Canonical bytes, hexadecimal |
| --- | --- |
| Unsigned zero | `00` |
| Unsigned one | `01 01` |
| Unsigned 127 | `01 7f` |
| Unsigned 128 | `01 80` |
| Unsigned 256 | `02 01 00` |
| Signed zero | `00 00` |
| Signed one | `00 01 01` |
| Signed negative one | `01 01 01` |

The enclosing schema determines whether a field is signed or unsigned and
supplies its admissible bound. Zero with a nonempty magnitude, leading-zero
magnitudes, truncation, and bytes beyond the enclosing field boundary fail.
All arithmetic uses the exact decoded value, without modulo reinterpretation.

No wrap, saturation, value loss, or representation-imposed terminal coordinate
is permitted. An exact unbounded height cannot fit a forever-fixed height field
or total block-byte ceiling. Role budgets therefore include explicit growing
coordinate/accounting allowances alongside bounded operation and work allowances.
This does not promise constant CPU or memory requirements for an indefinite
history.

Admission must establish the applicable authenticated context before using it
to bound variable data. A claimed height, length, version, or amount cannot
authorize its own allocation budget. Unknown-parent input requires bounded
deferral, refusal, or separately bounded acquisition before its variable body.
Length-prefix parsing itself must be bounded before magnitude allocation.

Successor bounds derive from actual transition semantics, such as exact parent
height plus one, authorized nonce consumption, or authenticated funds plus the
permitted issuance increase. Arithmetic-work limits account for operand lengths,
multiplication, division, normalization, and traversal, not only wire bytes.
Historical-certificate validation uses its exact historical snapshot.

Arbitrarily many timeout rounds can occur at one height, so finalized parent
height and balances do not bound every round coordinate. Unusually large round
certificates use a separate, incrementally bounded acquisition process. Each
step has predetermined byte, memory, storage and verification-work allowances
independent of the sender's claimed length or round. Partial evidence and peer
identity do not enlarge those allowances. Spilling to disk alone is insufficient.

Exceeding a local acquisition budget means not yet validated, not a mathematically
invalid round. Acquisition grants no round, vote, branch or finality authority.
Only complete verification of the exact context, immutable snapshot, distinct
signers, strict-greater-than-two-thirds threshold and corresponding phase under
`PROD-076` permits certificate-driven higher-round advancement. A proposal alone cannot do so
(`PROD-080`).

Budget growth, concurrent-request fairness, cancellation, retention and eventual
catch-up guarantees remain unfinished. A permanently fixed local ceiling cannot
support an unconditional promise of catching up to every finite valid round;
manual budget enlargement would make that promise operator-dependent. Exact
round admission and growing role budgets must resolve these obligations before
implementation.

## Genesis and integration boundary

The reusable genesis schema must preserve the selected construction sequence:
bootstrap-attribution domain, unsigned genesis root, exact ceremony-frozen
authorizations, and final genesis identity. Neither direct nor indirect state
fields may introduce a final-genesis hash cycle. Existing artifact-genesis
derivation is not the complete successor genesis schema.

Genesis has a separately specified finite installation/admission envelope.
Its initial account descriptors and authorizations follow the genesis contract;
ordinary post-genesis creation does not silently define genesis nonce handling.
Production keys, allocations, applicant records, and frozen ceremony signatures
are external facts and are not invented by this specification.

The foundational registration contract must be separated from later
rotation/recovery integration dependencies while preserving those requirements.
That approved separation does not remove unrelated fee, resource, genesis, or
canonical-parent prerequisites. The exact ledger decomposition remains part of
the implementation-scope review. No rule becomes implemented merely because
its architectural direction is selected here.

## Required specification and measurement work

Before canonical admission code is eligible, finish the complete state inventory,
record and operation schemas, identifier and signing preimages, integer-field
bounds, map proof format, version/context framing, and rejection order. Select exact
operation fees and protocol limits from the required economic model and measured
canonical bytes, signature verification, arithmetic, reads, and retained-state
growth. Preserve unresolved tail and boundary requirements until specified.

The measurement package must exercise the actual selected policy and decoding
algorithms, not only a cryptographic primitive. It must record machine,
architecture, pinned toolchain, optimization profile, corpus, sample method,
and separate construction/compilation from execution. Cover threshold extremes,
malformed and duplicate evidence, shared account roles, maximum distinct
authorizers, integer-width growth, Patricia paths and updates, and atomic
multi-operation failures. Measurements do not by themselves choose a deployment
hardware target, acceptable latency, fee schedule, or policy-size maximum.

The first eventual transition implementation must prove unchanged parent roots
on rejection, exact conservation, replay isolation, evidence-invariant operation
identity, permanent key reservation, role-separated escrow, and deterministic
successor commitments. Its publication scope must identify whether canonical
parent provenance and installation are implemented or remain external; a
caller-selected reference root or fee limit cannot be presented as canonical
authority or canonical fee adequacy.

### Account-operation measurement obligations

The following are structural obligations for the measurement corpus, not selected
resource coefficients or sufficient whole-operation cost bounds. Exact record
layout, proof representation, fee parameters, and transaction implementation are
still required before their complete costs can be measured.

For registration, let `A` be the set of distinct operator, bond-beneficiary, and
fee-payer accounts. Its size is between one and three. If account `a` has policy
threshold `M_a` among `N_a` keys, registration verifies
`sum(M_a for a in A) + 1` signatures: one threshold authorization for each distinct
authorizing account and one separately domain-bound consensus-key possession
proof. Account-role aliasing does not duplicate that account's authorization or
nonce. A receiving-only reward account adds no authorization signature.

The account-reference set is the union of `A` and the reward account, so it has
between one and four distinct accounts. Measurements must account for the
authenticated facts actually read and the selected representation of their
policies; a prevalidated-policy microbenchmark omits policy admission and state
proof work. Registration also requires the applicable registration/key-absence,
escrow, scheduling, fee-pool, and accounting facts and updates. Their exact
storage operations cannot be inferred from the signature count.

For non-artifact operation fee `F > 0`, `ECON-082` fixes validator-pool credit
`P = floor(F / 5)` and burn `F - P`. Let a registration bond be `B`. The combined
liquid-balance debit is `B + F`, escrow increases by `B`, the current-height
validator pool increases by `P`, and accounted live supply decreases by
`F - P`. The registration operation itself creates no issuance. If beneficiary
and payer are the same account, that account must fund the combined `B + F`;
checking the two amounts independently against one starting balance is invalid.
If they differ, each must fund its own debit. Authorization-only nonce updates
do not introduce another balance debit.

For sponsored account creation with initial funding `D >= 0`, the existing
sponsor funds `D + F`, the new account receives `D`, the validator pool receives
`P`, and accounted live supply decreases by `F - P`. The sponsor and new account
are distinct account identities because creation of an existing account fails.
The signature count is the sponsor threshold plus the new-policy threshold.
Creation consumes both account nonces under the specified creation convention;
it does not substitute the new policy's consent for the sponsor's debit
authorization.

The corpus must cover all account-role partitions, minimum and insufficient
balances, fee/bond combined-debit failure, invalid first and last signatures,
distinct qualifying signer subsets, repeated nonce pairs, duplicate creation
and key targets, and a failure after earlier speculative operations have
succeeded. It must measure authenticated reads and path updates, newly retained
record bytes, integer operand widths, and resulting fee-pool/burn accounting.
CPU caching or structural sharing must not change protocol outcomes or conceal
unmetered work, and the resource model must preserve `RES-046`'s prohibition on
charging one work unit to two payers.

### Initial measurement target

The initial engineering target is Linux x86_64, four CPU cores, 8 GiB RAM,
and SSD storage, aiming for at most one second of complete local block
validation. This is a measurement target, not a wall-clock block-validity rule
or a permanent hardware guarantee. Resource coefficients and admissible limits
remain undecided until complete representative and adversarial paths are measured.

The isolated `tools/state-measurement` prototype measures authorization primitives
and candidate integer decoders. It is not a canonical transaction implementation
and cannot establish the complete-block target. Its policy sizes are corpus
parameters, not proposed protocol maxima. It compares these decoder implementations,
not an inherent performance ordering of all possible encodings.

A hosted Linux run must record its actual CPU, physical memory, compiler, source
revision, and enforced CPU/memory/swap constraints. An 8 GiB process budget on a
larger host must be reported as such, not as physical 8 GiB hardware. These
in-memory primitives do not exercise SSD persistence or authenticated state I/O.
Compilation and runtime measurements must be reported separately.

Hosted Linux calibration may use four logical CPUs on a VM with fewer reported
physical cores and the enforced 8 GiB process budget. Such runs provide initial
calibration only. Validation against the four-physical-core complete-block target
remains a separate requirement; a hosted single-threaded primitive run does not
satisfy it.
