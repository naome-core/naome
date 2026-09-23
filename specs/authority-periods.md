# Authority periods: v5 data contract

This specifies the public authority snapshot and next-period key offer data
used by a future sealed validator handoff. The current `state-v4` run still
uses its genesis validators. Constructing, decoding, or verifying these v5
objects does not select a new authority or grant signing rights.

An authority snapshot has exactly four equal-weight slots and an effective
height. The slot identifier remains fixed when its occupant changes. A unit
has a stable identity, owner account, origin, and optional period keys. An
absent key binding makes the slot vacant for that period; the slot still
counts in the four-unit quorum denominator. Consensus and transport keys
must be distinct valid non-weak Ed25519 keys. A bound endpoint is a canonical
literal TCP socket address. Keys and endpoints cannot collide within one
snapshot. The four units must have distinct owner account IDs; this does not
prove that four different people control those accounts.

Bootstrap units derive their identity and slot from the original validator
identity. Their relative age is the explicit genesis retirement order. An
earned unit derives its identity from its paid completion family and inherits
a slot when a later handoff installs it. Bootstrap units are older than earned
units; earned units are ordered by their original completion ordinal. The
snapshot codec binds the genesis, effective height, slot, unit identity,
owner, origin, keys, and endpoint. Structural decoding does not prove that a
snapshot was selected by finalized history.

A next-period offer binds one existing unit, the current snapshot identity,
caller-supplied parent record and state commitments, and the immediately
following effective height. Selected history must separately establish that
the parent was finalized. Its owner account signs the offer. The proposed
consensus and transport keys each sign a separate possession transcript over
the same body. All three signatures must verify under their declared roles.
Both the consensus and transport keys rotate at every period boundary, even
when the same owner retains the unit.
An offer cannot be moved to another parent, height, owner, unit, endpoint, or
key pair.

A no-join successor is derived from three or four distinct offers in ascending
unit-identity order. The four slot identities and occupants remain fixed;
every unit without an offer becomes vacant. The derivation rejects reused
current-period keys, owner account keys, and keys in the selected state's
complete historical and registered-key set. The caller must provide that full
set and the selected account registry; a structurally valid successor alone
does not prove either input complete. Future join selection, READY and
TERMINAL certificates, key retirement, seal selection, and live activation
are separate contracts and are not implemented by this data layer.
