# NAOME local test-coin ledger

`naome-ledger` owns integer coin amounts, canonical signed transactions,
UTXO validation, revocable node spending rights, and a durable local journal.
It depends on `naome-wallet`, not on the gossip node or mathematical proof
packages. The node supplies its existing wallet custody and CLI adapter.

This is an isolated test ledger with worthless test coins. It does not issue
NAO, pay for work, implement mining, replicate balances, or choose a shared
transaction order across independent machines. Its initialization allocations
are explicit test fixtures, not a production issuance rule. A later production
protocol must choose consensus, finality, storage proofs, and issuance rules;
it must use a distinct signature and network domain.

## Use existing wallets and connect several nodes

Start each node once with its existing `NAOME_NODE_DIR`. This initializes an
independent wallet if it has never existed. Existing wallet files, addresses,
and ownership-proof commands retain their formats.

All commands below access the same **local** dedicated ledger directory. Use
absolute paths. Do not place the ledger inside a node directory, share the
private wallet key, or copy the SQLite files between running nodes. A busy
ledger rejects another simultaneous caller; retry after its owner closes it.
There is no cross-host synchronization or network-filesystem guarantee.

On the machine/account holding the owner wallet, explicitly create a test
allocation. Amounts are whole indivisible test units, with no NAO conversion:

```sh
NAOME_NODE_DIR=/nodes/owner naome wallet address
NAOME_NODE_DIR=/nodes/owner naome wallet test-coins init /test-ledgers/demo 1000
```

Obtain each worker node's own wallet address with `naome wallet address`.
Authorize both addresses from the owner wallet, then connect each worker:

```sh
NAOME_NODE_DIR=/nodes/owner naome wallet test-coins authorize /test-ledgers/demo <worker-a-address>
NAOME_NODE_DIR=/nodes/owner naome wallet test-coins authorize /test-ledgers/demo <worker-b-address>
NAOME_NODE_DIR=/nodes/worker-a naome wallet connect /test-ledgers/demo <owner-address>
NAOME_NODE_DIR=/nodes/worker-b naome wallet connect /test-ledgers/demo <owner-address>
NAOME_NODE_DIR=/nodes/worker-a naome wallet connection
```

Each node keeps its own private key. A connection contains only the ledger
path, network identity, owner address, and node signing address. One node has
one active connection; several nodes may connect to the same owner wallet.
Connecting does not grant rights: the ledger must already contain the owner's
signed authorization. Every grant confers full spending access to that wallet
in this test ledger. A node cannot grant access to another node.

Either connected node can spend from the owner wallet. Change returns to the
owner wallet. Payments to its address also increase that wallet's balance;
there is no special or self-authorized work-credit operation.

```sh
NAOME_NODE_DIR=/nodes/worker-a naome wallet test-coins send /test-ledgers/demo <recipient-address> 300
NAOME_NODE_DIR=/nodes/worker-b naome wallet test-coins balance /test-ledgers/demo
NAOME_NODE_DIR=/nodes/owner naome wallet test-coins balance /test-ledgers/demo <recipient-address>
```

`prepare` accepts the same arguments as `send`, prints a signed transaction,
and leaves the ledger unchanged. `submit <ledger-dir> <transaction.json>`
checks and records such a transaction without needing a private key. All
successful test operations identify their `local_test_coins` scope; a prepared
transaction binds its test network in the signed payload. Use `--json` before
`wallet` for consistency with other machine-readable node commands.

The owner can revoke an individual node. Other node grants remain active:

```sh
NAOME_NODE_DIR=/nodes/owner naome wallet test-coins revoke /test-ledgers/demo <worker-a-address>
NAOME_NODE_DIR=/nodes/worker-a naome wallet connection
```

`wallet disconnect` durably revokes a connected delegate's own grant before
removing its public connection. It requires the ledger to be available. An
owner disconnect only removes its local connection; its main key still owns
the wallet. Reconnecting a revoked worker requires a new owner authorization.
A new grant cannot revive payments prepared under an earlier grant epoch.
Revocation affects future admission, not previously committed payments.

## Validation contract

- Amounts use `u64` units and checked arithmetic. Outputs and payments must be
  positive. Input and output sums must match exactly; there are no fees or burns.
- A payment uses at most 128 inputs and 128 outputs. Inputs must be distinct,
  unspent, and owned by the payment's stated wallet. Input selection is
  deterministic. The signing key must be the owner or a currently authorized
  node, with the exact current grant epoch.
- Only an owner key can grant access. An owner can revoke any of its node keys;
  a node can revoke itself. Each access change uses the next owner sequence.
- Every signature binds version, test network, signing address, operation,
  consumed outputs, and created outputs or the complete access change.
  Ownership challenges cannot authorize payments.
- Validation runs before mutation. Rejections leave both balances and the
  committed journal unchanged. The local selected order admits at most one
  of two transactions spending the same output. Network consensus is still
  required for independent nodes to choose the same order.

## Canonical bytes

All integers below are unsigned, big-endian. Addresses are their canonical
32-byte Ed25519 public keys. JSON is the bounded interchange representation;
identities are computed from the following binary layout, independent of JSON
field order or whitespace.

A network ID is SHA-256 of `naome:test-ledger-genesis:v1\0`, version `u8`,
instance nonce `[u8;32]`, output count `u16`, then each address and amount `u64`.
Genesis outputs become outpoints `(network_digest, output_index_u32)`.

A transaction ID/signing digest is SHA-256 of
`naome:test-ledger-transaction:v1\0`, version `u8`, network ID `[u8;32]`, signer
address, then one operation:

- Payment tag `0`: owner address, grant epoch `u64` (zero for the owner key),
  input count `u16`, each transaction ID `[u8;32]` and output index `u32`, output
  count `u16`, then each address and amount `u64`.
- Access tag `1`: owner address, delegate address, sequence `u64`, enabled byte
  (`0` or `1`).

The wallet signs `naome:test-ledger-signature:v1\0` followed by that digest,
using strict Ed25519 verification. Signatures are canonical lower-case hex;
transaction and network IDs are 32-byte lower-case hex. Every `\0` above means
one zero byte. Current format version is 1; other versions are rejected.

The journal starts at the network ID. Each admitted transaction updates its
root to SHA-256 of `naome:test-ledger-journal:v1\0`, previous root `[u8;32]`, and
transaction ID `[u8;32]`. The stored count and root bind the complete order.

## Persistence and limits

On supported Unix targets, `Ledger` owns one private directory and exclusive
filesystem/SQLite locks. SQLite stores the genesis, ordered signed operations,
and committed count/root in one transaction. No private wallet material is
stored in the ledger. Each open replays and verifies every operation, checking
signatures, value conservation, rights, ordering, canonical records, and the
committed count/root. No stored balance or checked flag is trusted.

Each genesis/transaction record is limited to 64 KiB. SQLite's page cache is
1 MiB, temporary storage uses files, and memory mapping is disabled. Replay
streams records; active UTXOs and grants remain in memory. No scale or
performance qualification is claimed for large histories.

The database uses DELETE journaling, `synchronous=EXTRA`, and `fullfsync=ON`.
EXTRA also synchronizes journal removal as described in the
[SQLite durability contract](https://www.sqlite.org/pragma.html#pragma_synchronous).
Success is returned only after commit. An uncertain commit poisons the handle;
reopen reconstructs whether the transaction was committed. Tests terminate a
real child process before and after commit and verify recovery. This does not
constitute a physical power-loss test.

Missing or corrupt established database/receipt files are errors, never a
fresh allowance. A validated empty initialization stage can resume without
changing its genesis. Back up the dedicated ledger directory only while it is
closed. Restoring an older, internally consistent backup rolls back local test
history; detecting that requires an external accepted-state witness.
