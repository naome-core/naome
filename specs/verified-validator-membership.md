# Verified validator membership

## Selected policy

Validator authority belongs to explicitly admitted independent organizations.
Each admitted organization has one vote and one proposer share. A membership
snapshot contains 4–256 organizations; its quorum is `floor(2*N/3) + 1`, counting
offline organizations in N. Both operator approval and block finalization need
that quorum, which is always at least three organizations. There is no emergency
quorum reduction, privileged administrator, automatic admission, bond-based rank,
or Knowledge Weight voting power in this profile.

Anyone can generate keys, run an observer, synchronize verified history, and
submit an application. Keys prove possession, not organizational independence.
The existing operators must check the applicant's real-world identity and
independence before explicitly approving the exact application. Multiple keys,
accounts, servers or organization labels do not establish independence. The
protocol cannot detect undisclosed common control; the security assumption is
fewer than one third Byzantine admitted organizations, with independent key
custody and eventual network delivery for progress.

This is a pre-release feature named `verified_membership`. Its initial wire
identifier is zero, not a product release or a third generation of the economic
draft. The existing fixed-validator development profile and its byte formats
remain separate. No existing journal, certificate or snapshot can be converted
into membership authority by changing a configuration field. The unfinished
account/economic draft does not define voting power for this profile.

## Identity, genesis and approvals

An organization record is exactly four 32-byte fields in this order:
organization identifier, Ed25519 consensus public key, Ed25519 operator-approval
public key, and Ed25519 Noise network public key. The organization identifier is
nonzero. All three keys must be valid non-weak Ed25519 keys, distinct within the
record and across the active set. Organizations are strictly sorted by their
full identifier and occur once. Rotation is not an implemented operation;
replacing an organization requires the ordinary approved removal and join rules.

The caller-trusted genesis contains the complete organization records and the
artifact-chain definition. The membership context hashes the artifact-chain ID,
the epoch width 8192, the `u16` member count, and the ordered records under
`naome/verified-membership/v0/genesis\0`. The genesis ancestry has a separate
`genesis-ancestry` domain. Genesis height is zero and membership generation is
zero. Deployment operators must distribute and independently compare this
genesis/context; a peer status message cannot supply trusted genesis.

Every request binds context, current generation and current snapshot ID. Its
action is one of:

| Action | Required applicant/target authorization | Current operator approvals |
| --- | --- | --- |
| Join | Possession signatures from all three proposed keys | Current quorum |
| Voluntary exit | Target organization's approval-key signature | Current quorum |
| Forced removal | No target signature | Current quorum |

Approvals use operator keys, not consensus keys. The approval signs the request
ID, which hashes the complete canonical request including possession witnesses.
Operators explicitly approve a displayed/exported request ID; receiving a
request, approval, proposal or certificate never invokes an operator key.
Approvals from duplicate organizations, a different generation, a different
request or a different deployment cannot accumulate toward a quorum. A forced
removal therefore remains possible without the departed organization's key,
provided the unchanged current quorum is available. Removing from a four-member
set is refused; another independent organization must first join and activate.

## Finalization and activation

An approved request is not a membership change until included in a strictly
validated artifact proposal and finalized by current consensus keys. A proposal
contains exactly one normal artifact block and zero or one approved membership
request. Complete approval witnesses are part of the proposal value, not detached
finalization evidence. Requests do not create empty blocks.

For positive height H, epoch E is `floor((H-1)/8192)`. A change included at H
activates for height `(E+2)*8192+1`: it is excluded throughout E and E+1. Thus a
join included at H1 first participates at H16385, after H16384 has been durably
finalized. A removal included at H16385 first applies at H32769. Local clock
time, reaching the end of a timeout, collecting approvals and editing bootstrap
peers cannot accelerate this rule. Checked arithmetic rejects overflow.

There is at most one pending change. This serializes changes and prevents a
batch of independently admissible removals from taking the set below four.
The successor generation increments by one. Once the pending transition becomes
active, the same height may finalize another request approved by the newly
active set, with a new E+2 delay. Stale requests/approvals are dropped locally.

The selected parent branch derives the exact next-height snapshot before
evaluating a proposal. The last old-set block authorizes the first new-set
height; its durable selection precedes any new-set key use. A joining key remains
an observer until it has verified and durably replayed that prefix. A removed
key automatically becomes an observer at the same boundary. Neither side gets
to choose a quorum denominator from its peer connections or local availability.

The existing exact proposer-priority arithmetic is used with unit weights.
At a set transition, retained keys keep their priority, removed keys disappear,
new keys receive the defined newcomer priority, and the existing normalization
runs. Proposal values commit the deterministic round-independent next priority
root. Round proposers are derived by sequential arithmetic from the same parent;
changing rounds does not change a previously locked proposal value.

## Proposal, voting and finality contract

The proposal value binds context, height, parent consensus ancestry, active
snapshot ID, unchanged artifact block, resulting membership-state commitment,
proposer-state commitment, and the optional complete approved request. Its
`proposal-root` and `ancestry` hashes use distinct domains. Current-height
producer and vote signatures do not enter either value hash.

A producer signature binds context, height, round, parent, snapshot, value root,
and the presence and digest of its complete earlier-round prevote certificate.
That certificate must name the same root at a strictly earlier round. Removing
or replacing its evidence invalidates the producer signature. A proposal also
requires the exact scheduled proposer and full canonical mathematical artifact
validation against the selected parent. No partial validation grants a vote.

Prevote and precommit signatures have distinct domains. Each binds context,
height, round, parent, snapshot, role, and nil or one proposal root. A certificate
contains one shared coordinate and strictly sorted distinct consensus-key/
signature pairs. Every signature is verified directly with strict Ed25519;
there is no aggregate-signature or key-possession shortcut. Finality requires a
non-nil precommit quorum, its same-round signed proposal, and complete artifact
payload. Different valid signer subsets may prove the same selected value.

The event machine preserves locks and valid values across increasing rounds.
An acceptable current proposal produces one prevote. A conflicting locked value
produces nil unless a valid earlier-round certificate permits unlocking. A
proposal prevote quorum permits one locked precommit; a nil quorum or the exact
local timeout permits nil precommit. More than one third authenticated higher
round participants or a verified higher-round certificate permits catching up
to that round. Complete finality can select a verified direct successor from any
phase. A known non-nil precommit quorum freezes further key use while its full
proposal is missing.

Round and retained-evidence limits are explicit. Ordinary future vote/proposal
retention is restricted to the current round and seven following rounds; stale
nonfinal certificates cannot consume current-round capacity. Locked/valid values
and useful finality evidence have independent retention semantics. Exceeding a
local resource bound grants neither a new vote nor a lower quorum. These bounds
are operational limits, not a proof of indefinite adversarial liveness.

## Durable ownership, recovery and conflicts

One exclusively locked journal/anchor pair owns the selected branch, event
machine and optional consensus key. A journal header binds trusted genesis,
the exact signing key or observer mode, and configured lifetime limits. Every
transition is first prepared without key use, encoded in full, written and
synchronized, committed and synchronized, and independently anchored and
synchronized. Only then may its exact opaque signing intents be completed.
Completion signatures are verified against those intents and likewise persisted
and anchored before publication. Parent and membership IDs are authenticated
inputs, never extra anti-equivocation slot dimensions.

Restart verifies the entire sequence, all branch transitions, signatures and
artifact payloads. It reconstructs pending activation, proposer priorities,
locks, exact signing intents and retained publication bytes. A torn uncommitted
trailer may be removed only at the verified anchored prefix. A complete journal
record ahead of its anchor requires explicit paired recovery; a newer anchor
can never be repaired by rolling the journal backward. Recovery advances an
anchor only after complete replay, and completes only an already recorded exact
intent. There is no fresh-genesis reset or discard-the-locked-value recovery.

Every historical complete finality proof received through the node/network
boundary is checked for conflict with selected history. A different value must
first authenticate under that historical snapshot's unchanged quorum, then pass
complete historical-parent replay and artifact/proposal verification. A valid
conflict is recorded as an anchored terminal event. It chooses neither branch,
prevents all further key use, and remains terminal after normal or recovery
restart. A terminal event also suppresses completion of any pending signing
intent while preserving that preparation in the journal. Invalid accusations
do not change authority. A same-value historical retransmission grants no new
authority. Historical nonfinal votes alone are not a finality-conflict proof.

Proof serving reads indexed committed proof bytes and checks their recorded
digest. Source mutation poisons the owner. Journal, anchor and lock files are
opened with no-follow protections and descriptor checks; Unix writable
files must be regular and single-linked. Durable membership ownership requires
Unix directory synchronization; other platforms refuse creation, opening and
recovery before touching owner files. Parent directory ownership and custody
of both independently retained stores remain operator responsibilities. The
pair detects inconsistent truncation; restoring both to a matching old backup
is not a safe way to restore a live signing key.

## Transport, inbox and catch-up

`/naome/verified-membership/0` uses TCP, Noise and Yamux. Authenticated peer identity
is bound into each handler codec before frame decoding. Active network keys
share an eight-frame bounded decode lane; unknown observers share a separate
two-frame lane. Observer traffic cannot consume the validator decode lane.
Membership refresh changes subsequent lane admission and bounds former-member
observer connections. Connection, stream, frame-size, aggregate retention,
request, peer pacing and publication limits apply independently.

Requests carry a publication, application, approval, candidate, context status
query, or exact-height finality query. Status replies are hints. Catch-up asks
for one next-height proof, correlates context/height/parent, and verifies it
through the same durable owner before advancing. Failed sources are paced and
rotated; status and gossip get separate service turns. Bootstrap addresses are
connection hints, not voting authority. Incoming observers can apply without
being preconfigured in every old node.

The local application inbox holds at most 16 requests; approval lists are
bounded by the active-set cap. Network saturation does not evict operator work.
An explicit operator import may replace an unapproved request, and explicit
local `reject`/`allow` commands manage up to 256 blocked request IDs. Rejection
does not revoke an approval already published to other nodes. The JSON inbox is
atomically persisted and revalidated on startup; a failed save stops the process
before another gossip turn. Candidate retention is separately bounded and
ephemeral; files or peers must resupply nonfinalized candidates after restart.

All binary integer fields are big-endian; framed messages have exact domain
prefixes, explicit bounded lengths/counts and no accepted trailing bytes. The
authoritative layouts and numeric bounds are in `verified_membership/{mod.rs,
codec.rs,state.rs,evidence.rs,branch.rs,machine/codec.rs}` in `naome-consensus`
and `transport/verified_membership/codec.rs` in `naome-network`.

## Evidence and applicability

Core tests cover strict thresholds, identity aliasing, signature/codec mutation,
approval replay, delayed join/exit/removal, and bounded round processing. Storage
tests cover exact signature restart, pending-intent recovery, anchor gaps,
corruption, file substitution and terminal historical conflict. Transport tests
hold observer frames open while validator decoding continues. Process tests use
five separate validator processes for application, explicit approvals, artifact
finalization, proof export and strict observer restart.

The explicit release qualification replays 32,770 actual finalized heights into
five independent journal/anchor pairs, using at most five parallel owners to
overlap I/O without skipping any signature, artifact or synchronization check.
Prefix blocks use generated canonical
proofs and fully verified quorum certificates; they do not replace height or
epoch constants. At H16384/H16385 and H32768/H32769, real Noise/TCP runtimes
finalize candidates, with a partition at activation and subsequent verified
catch-up. The test finally reopens all five journals independently from trusted genesis
in parallel.
This is local multi-node evidence, not a geographic deployment or a claim that
every prefix height was finalized by live network processes.

Production genesis organizations/public keys, indefinite storage lifecycle,
hardware/remote signing, account balances, rewards, fees, bonds, key rotation,
economic delegation and permissionless contributor APIs remain separate work.
See `verified-membership-operations.md` for setup and explicit recovery.
