# Authority periods and sealed handoff (state-v5)

A selected parent at height `h-1` contains the authority snapshot `S_h` for
record `h`. It has four equal-weight slots. A vacant slot has no signing key but
still counts in the denominator: agreement, time, READY, and TERMINAL each need
at least three distinct eligible signatures. The slot identifier survives owner changes;
its occupant has a unit identity, owner account, origin, and period keys.
Distinct owners are distinct accounts, not evidence of distinct people.

The initial units and their retirement order come from genesis. Bootstrap age
uses that explicit order; an earned unit's age is its original paid-completion
ordinal. A candidate derives its unit identity from the completed family and
inherits the oldest unit's slot when installed. At most one earned claimant
replaces one unit per record. The lowest paid-completion ordinal among eligible finalized intents has priority.
An absent candidate offer selects a no-join rotation and leaves the queued
claim in place, subject to its original expiry. A revised intent keeps its
original queue position and expiry. An expired, consumed, or stale claim grants
no admission. An intent alone grants no signing or voting weight.

## Exact record and successor

Every record carries a bounded `HandoffPlan`: three or four owner-authorized
`NextPeriodKeys` offers from current units, plus at most one
`CandidateAdmissionOffer`. Each offer binds genesis, the exact selected parent
record and state, outgoing snapshot, immediately following effective height,
unit or claim, new consensus and transport keys, and a canonical literal
endpoint. The current owner signs a rotation offer; the candidate owner signs
an admission offer tied to the exact finalized intent receipt. Both proposed
keys prove possession in distinct signing domains. The selected parent's
account registry and complete used-key history reject reused keys, including
owner keys. All active consensus and transport keys rotate every height.

Admission rejects an endpoint occupied in either the outgoing roster or the
proposed successor, as well as another pending intent. A retired genesis
endpoint is reusable once neither live roster occupies it; historical keys
remain permanently ineligible for reuse.

The plan is part of the agreed record and its resulting state commitment. It
is never added after agreement. Deterministic execution derives `S_(h+1)`
from the exact plan, preserving four stable slots and making a missing rotation
slot vacant. At least three valid rotation offers are required even if a
candidate joins. The candidate must match the oldest eligible queued intent's
owner, keys, endpoint, receipt, and unconsumed claim. The record at `h` is
agreed under `S_h`; its successor is not selected until sealed.

## Two quorums and local retirement

A verified agreement yields a seal context that binds genesis, height, record,
previous and next state commitments, and both snapshot IDs. Incoming members
verify the predecessor history and agreed record, durably stage this exact
context, then at least three members of `S_(h+1)` sign READY. Outgoing members verify
READY, durably save exact TERMINAL signatures, stop old consensus and TIME
signing, retire their locally controlled old period secret capabilities, and
release the saved bytes. At least three members of `S_h` sign TERMINAL. Only a finality
envelope containing the agreed proposal, precommit quorum, and both seal
quorums installs the selected successor.

After durably staging agreement, a node pauses ordinary proposals, votes,
time reports, and round timeouts while it exchanges preparation and retirement
evidence. The saved agreement survives restart and remains bound to its exact
parent. This pause does not retire the outgoing key; durable retirement still
requires the READY quorum and the TERMINAL sequence.

A restart may resend saved READY or TERMINAL bytes. It cannot select a competing
prepared offer set or recover an old signer after retirement. An anchored
period offer never regenerates missing secret keys. The active signer opens
only for a fully selected history state; an agreed but unsealed state grants
no ordinary next-period signing. A missing slot can block progress without
reducing the quorum threshold. A failed handoff never silently rolls back
finalized history.

Transport keys rotate with consensus keys. A bounded staged transport can
relay HANDOFF and REPLAY before selection; it has no ordinary voting authority.
Old transport identity is closed before TERMINAL release. The local custody
claim covers files controlled by this implementation; external backups and
regenerating seeds require operator attestation and are part of the exposure
assumption, not something the software can erase remotely.

An outgoing owner whose fresh offer is omitted still owes its outgoing terminal
signature when a READY quorum exists. After retiring the old transport it can
deliver that saved signature over fresh owner-authenticated recovery transport.
Recovery challenge responses bind the chain, recipient, nonce, owner and fresh
transport key. They permit bounded history and handoff exchange, including
pending agreement retrieval, and grant no ordinary consensus or time authority.
A node that alone selects a seal may itself become vacant in that successor.
It continues relaying the complete finalized proof over these authenticated
recovery connections, in either direction, so prepared peers can select the
same history. Each receiver verifies the proof against its selected parent.

After the finite run's terminal record, live and restarted nodes bind their
configured primary address using a fresh recovery-only identity. This bounded
owner-authenticated history service lets a cold peer fetch the terminal proof
after all period signing keys and old Noise sessions have been retired.

## Candidate provisioning and evidence boundary

`naome candidate-setup` takes an existing owner key and the exact candidate
consensus and transport keys used by a finalized join intent. It independently
replays a finalized export, checks the live claim and exact intent, creates a
private observer history and anchored candidate custody, and records primary,
handoff, and explicit recovery endpoints. Source candidate key files are
removed after durable import. The owner key remains separate. Candidate
startup has no ordinary signer until a sealed selected period installs it.

The v5 code and local tests implement these checks. A local replay or
four-process rehearsal does not demonstrate separate-machine operation,
long-running availability, or erasure of external backups. The verification
record must report test, CI, Docker, and physical-host evidence separately.
