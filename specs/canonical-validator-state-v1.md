# Canonical validator-state foundation V1

## Status and applicability

This is a draft protocol contract for the canonical account and validator-state
foundation. It records selected semantics and identifies the byte-level,
resource, economic, and integration requirements that remain unspecified.
It is not an implemented consensus profile, a production genesis, or evidence
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
identities. The broader wording of `CODEC-046` and `CODEC-047` must be reconciled
explicitly with this current-height distinction when their successor contract
is finalized; prior-height settlement evidence is committed execution input.

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
Cancellation of pending changes requires its own exact contract before support.

Either the operator or the bond beneficiary may request delayed exit. The
beneficiary may request bond reduction and may withdraw only released principal
under the selected backing and liability rules. The operator's consent at
registration includes these beneficiary rights.

A request is distinct from an effective change and from withdrawable value.
Exit or reduction does not shorten offense liability. The existing
30-complete-epoch liability window, complete offense-liable forfeiture, and
lineage-wide permanent tombstone rules remain binding. Exact exposure records,
epoch endpoints, reduction scheduling, and penalty/withdrawal ordering remain
unfinished; these rights do not imply those operations are implemented.

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

The position uses its immutable authorization snapshot derived before that
position. Prior-height settlement executes first using the corresponding
historical weight, delegation, and commission data; the first height uses its
genesis sentinel. The operation stream follows, and artifact publication runs
last. Same-block delegation, registration, or rewards cannot retroactively
authorize the block or alter prior-height settlement inputs.

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

Rounds require a separate acquisition and catch-up contract: arbitrarily many
timeout rounds can occur at one height, so finalized parent height and balances
do not bound every round coordinate. A round supplied by an untrusted sender
cannot determine its own pre-allocation allowance. Exact round admission,
growing role budgets, and operational refusal semantics remain unfinished.

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
