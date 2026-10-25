# Node lifecycle and computation

See [networking and security](NETWORKING.md) for automatic Internet discovery,
encrypted transport, public graph visibility and trust boundaries.

`naome start` starts the node. The resource governor automatically pauses
productive computation when resources or operating-system policy require it,
and resumes it after a stable recovery window. `naome stop` ends the node.
`naome interest <text>` remains available while computation is paused.

`naome status` reports network readiness separately from computation:

- `running`: computation can proceed within the installed resource budgets.
- `pausing`: new computation is closed; an admitted step is still draining.
- `paused`: admitted computation has reached a safe boundary.
- `stopped`: the node is not running.

`naome --json status` exposes `computation` and `computation_reason`. The reason
is null while computation is running or the node is stopped. A pause may first
report `pausing`; existing provider steps finish at their confirmed checkpoint
boundary. Original deadlines, reservations and work-unit accounting continue to
apply during a pause. A non-cooperative step remains subject to its existing
process supervisor and cleanup limits.

During a pause, the node defers generation, solving, interest assessment,
new proof intake and expensive validation. Gossip, discovery, peering and bounded
delivery of already checked proofs remain active. No unchecked proof becomes
accepted. Existing queue, protocol, peer and transport limits remain binding.
A real memory shortage can still refuse a network allocation; network service
never bypasses the installed shared capacity.

The same governor decision controls ordinary work and provider boundaries.
There is no separately persisted manual pause state. Restart re-observes current
conditions and revalidates stored proofs through the existing startup path;
a restart does not grant new time or work to retained obligations.

See [the resource policy](src/resources/README.md) for capacity ownership,
pressure signals and recovery behavior. Native energy or CPU savings have not
been measured.

## Wallet identity and key control

The first successful node initialization creates an independent Ed25519 wallet.
The standalone [`naome-wallet`](../naome-wallet) crate owns keys, addresses, and
key-control proofs; this node owns private-file custody, recovery, and the CLI.
`naome wallet address` reports its checksummed, lower-case Bech32m `nao` address;
`naome --json wallet address` reports the public identity receipt. No name,
identity document, registration service, or central account issuer is involved.
The address and any information shared with it are pseudonymous, not anonymous.

The wallet key is separate from the libp2p transport key. It persists in
`wallet.key`, with its public address in `wallet.json`, under `NAOME_NODE_DIR`.
The private key is an owner-only file and is never printed, gossiped, or included
in lifecycle evidence archives. It is not passphrase-encrypted; host and disk
security remain necessary. Back up both files securely. A missing established
private key, a mismatching address receipt, corruption, or unsafe private-key
permissions cause initialization and signing to fail rather than rotate the key.
An interrupted first initialization retains and recovers its completed key.

An independent verifier can issue a fresh key-control challenge without a node:

```sh
naome wallet challenge research.example/key-control > challenge.json
```

The wallet owner inspects the audience and signs that challenge:

```sh
naome wallet prove challenge.json > ownership.json
```

The verifier supplies the address it expected and its original challenge:

```sh
naome wallet verify <expected-address> challenge.json ownership.json
```

The signature binds the wallet address, verifier audience, and 256-bit nonce to
the `naome:wallet-key-ownership:v1` domain. The verifier owns challenge freshness,
expiry policy, and single-use tracking; the offline verification command does
not consume a challenge. Never use a challenge copied from the submitted proof
as the expected challenge. These proofs demonstrate key control, not an
authenticated person, unique node operator, coin balance, or payment.

The explicit [`naome-ledger` test-coin workflow](../naome-ledger/README.md)
uses these existing wallets for local payments and revocable spending access
from several nodes. `wallet connect`, `wallet connection`, and
`wallet disconnect` manage the public node association; `wallet test-coins`
provides initialization, balance, payment, and authorization commands. The
normal node does not create test coins or reward work automatically. This is
local test bookkeeping; network-wide settlement still requires a separately
specified and implemented shared ledger ordering and consensus.
