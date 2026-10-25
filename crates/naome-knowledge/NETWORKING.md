# Knowledge node networking and security

The ordinary node discovers local peers through mDNS and uses the public IPFS
Amino DHT as a **client** to discover Internet participants. No participant
roster, account, private key upload, or NAOME-operated server is required. Public
bootstrap infrastructure is an availability dependency, not a mathematical
authority. The pinned public bootstrap identities come from the IPFS Foundation's
[public utilities](https://docs.ipfs.tech/concepts/public-utilities/#amino-dht-bootstrappers).

The DHT participation key is a SHA-256 multihash of a NAOME namespace and the
current mathematical compatibility fingerprint. It advertises participation,
not private interests or proof contents. The node does not serve the public
DHT's arbitrary records. Compatible proof peers must still advertise NAOME's
exact protocol and independently pass every receiver-side mathematical check.

Public DHT peers advertising circuit-relay v2 can be selected as bounded relay
candidates. An accepted reservation creates a reachable, Noise-protected circuit
address. Failed candidates are backed off and replaced. DCUtR can upgrade a
circuit to a direct connection. Discovery, relay capacity, NAT traversal and
public infrastructure availability are separate concerns: a successful DHT
lookup alone does not establish reachability. Unsupported or restrictive NATs
may require a working relay. No particular relay's uptime is guaranteed.

## Transport and publication

TCP connections and relayed proof circuits require authenticated Noise
encryption. A relay cannot decrypt proof traffic between the end peers. A peer
identity proves possession of its key; it does not establish honesty, unique
human membership, or proof validity. Transport authentication, content hashes
and mathematical checking are independent boundaries.

The checked proof graph is **public to compatible peers**. Inventory queries and
content requests have no private-object ACL. Do not put confidential proofs or
questions into this public graph. Local owner interest text is not a wire field,
but requested content and participation can reveal interests. Public discovery
reveals peer IDs and reachable addresses. mDNS is unencrypted LAN discovery;
Noise does not hide IP addresses or traffic timing.

Node state directories are restricted to their owner (0700). Identity keys,
owner preferences, control endpoints and logs are created with owner-only file
permissions. Local files are not application-encrypted; disk encryption and
protection of the operating-system account remain separate controls.

## Untrusted routing and resource pressure

Untrusted routing hints cannot authorize loopback, private, link-local,
documentation, multicast or special-use addresses. DNS names are checked again
at the final resolved TCP endpoint before a socket is opened. Explicit literal
endpoints and mDNS-observed LAN endpoints are narrow exceptions; they do not
authorize other local services or additional ports. Only one relay hop is
accepted. Relays and DHT hints confer no proof-admission authority.

Authenticated connections are bounded by observed IPv4 /24 or IPv6 /64 origin,
with additional handshake-rate limits. Incoming identities cannot consume the
outbound contact reserve. Unreachable hints can be replaced by authenticated
connections. Unpinned proof connections have finite leases; pinned infrastructure
and the bounded set of selected relays follow their connection and reservation
lifecycles. These measures limit inexpensive identity churn and persistent slot
occupation. They do not establish complete Sybil resistance against an attacker
controlling many independent networks or all available bootstrap infrastructure.

Proof frames, streams, pending connections, relay circuits, work queues, memory,
disk and checker work retain their existing resource limits. A saturated
transport handoff returns retryable busy responses to new requests and applies
bounded backpressure to critical events rather than terminating the node.

## Configuration and verification

`discovery.internet` and `discovery.dht` default to `true`. An empty bootstrap
list in this mode selects the built-in pinned public bootstrap identities.
`discovery.mdns` independently controls LAN discovery. For an isolated NAOME
DHT, set `internet` to `false` and configure its own bootstrap peers. The explicit
`allow_private_addresses` option is intended for controlled isolated networks;
leave it disabled for public operation. Ordinary nodes need no manual
publish/follow commands.

Deterministic address/admission regressions and loopback attack tests belong to
the normal local suite. Existing process fixtures cover mDNS, isolated DHT,
relay exchange, DCUtR outcomes, malformed objects and recovery. The bounded
`tests/support/internet_discovery.py` fixture exercises real public discovery
without injecting participant addresses; one-host runs do not qualify physical
multi-host or NAT operation. Never substitute successful unit tests for those
operating observations. CI audits the locked dependency graph against RustSec
and fails for known vulnerabilities or unsoundness advisories.
