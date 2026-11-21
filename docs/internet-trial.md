# Connect two REP laptops through a known entry point

Use the same REP build on two laptops (A and B) and a reachable rendezvous and relay service (R). R can run on a public host, or in a separate node directory on a laptop with a public TCP port forwarded to it. Both laptops need outbound TCP access to that port. R must stay online during discovery and relaying. Choose a new directory per role. Each process creates its own private identity key.

The commands below use a POSIX shell and `jq`. Place the executable for each machine in the working directory as `./naome`. A macOS ARM64 build runs on Apple Silicon. On a Linux relay host, build the same checkout with `cargo build --release --locked --bin naome` and copy `target/release/naome` to the working directory.

## Initialize the three identities

On A, set `NODE_DIR="$PWD/A"`. On B, set `NODE_DIR="$PWD/B"`. On R, set `NODE_DIR="$PWD/R"`. In each shell run the following commands.

```sh
./naome --version
./naome --directory "$NODE_DIR" archive init
```

Exchange the three printed `peer_id` strings over a trusted channel. Set `A_ID`, `B_ID`, `R_ID` and `R_IP` in the corresponding shells. `R_IP` is the actual public IPv4 address reaching R. This example uses TCP port 41001. Allow inbound TCP 41001 in the host and perimeter firewalls. When using port forwarding, map public TCP 41001 to TCP 41001 on R. A connection behind carrier-grade NAT usually needs a separate publicly reachable host for R.

## Configure R

Write R's configuration and start it. The clients list admits A and B to the routing service. An empty replication peer list keeps the service outside the archive group.

```sh
cat > "$NODE_DIR/node.json" <<EOF
{
  "listen": "/ip4/0.0.0.0/tcp/41001",
  "peers": [],
  "discovery": {
    "mode": "server",
    "clients": ["$A_ID", "$B_ID"],
    "external_address": "/ip4/$R_IP/tcp/41001"
  }
}
EOF
./naome --directory "$NODE_DIR" start --json
```

## Configure A and B

On A, set `OTHER_ID="$B_ID"`. On B, set `OTHER_ID="$A_ID"`. Run these commands on each laptop. Their individual configurations contain only the other custodian's identity and R's pinned identity and address.

```sh
cat > "$NODE_DIR/node.json" <<EOF
{
  "listen": "/ip4/0.0.0.0/tcp/41011",
  "peers": [{"id": "$OTHER_ID"}],
  "discovery": {
    "mode": "client",
    "bootstrap_id": "$R_ID",
    "bootstrap_address": "/ip4/$R_IP/tcp/41001"
  }
}
EOF
./naome --directory "$NODE_DIR" start --json
./naome --directory "$NODE_DIR" status --json |
  jq --arg peer "$OTHER_ID" '{route: .connections[$peer], addresses: .discovered_addresses[$peer], sync: .sync.state}'
```

Read status again after discovery. A `direct` route means the authenticated connection to the other laptop uses TCP directly. A `relay` route means the connection uses a Circuit Relay v2 reservation on R with an end-to-end Noise session. R's `events.jsonl` records the two endpoint IDs in `relay_circuit`. An initial null route means that the two laptops have yet to establish a connection.

Each laptop registers a signed peer record at R. It can advertise eligible local listen addresses, the address R observes via Identify and its reserved circuit. Direct addresses are tried first when available. A failed direct dial permits the next attempt to use the reserved circuit. A peer advertising only a circuit can be reached immediately through R. The direct candidate reported by a NAT can expire or be unreachable. For a known public port mapping on a laptop, add `"external_address": "/ip4/PUBLIC_LAPTOP_IP/tcp/EXTERNAL_PORT"` to that client's discovery settings. An explicit address takes precedence over automatic direct address advertisement. Restart the node to apply configuration changes.

R learns peer IDs, registered addresses, connection timing and circuit endpoints. Archive catalogs, release gossip and object responses require a separate replication peer entry on both endpoints. Discovery alone grants access to routing. Set `"use_relay": false` on both clients for a direct-only trial. The default excludes private and special-use addresses from discovered direct routes. Set `"allow_private_addresses": true` only for an intended private network or loopback trial.

## Fetch one piece of evidence

On A, publish a small payload and its inventory. Send B the printed identifiers and checksum for verification.

```sh
printf 'calibration sample 10000 10260 um\n' > sample.txt
BLOB=$(./naome --directory "$NODE_DIR" archive blob sample.txt | jq -r .)
HEAD_ID=$(./naome --directory "$NODE_DIR" archive snapshot internet-trial | jq -r .)
./naome --directory "$NODE_DIR" archive publish "$HEAD_ID"
printf 'HEAD_ID=%s\nBLOB=%s\n' "$HEAD_ID" "$BLOB"
shasum -a 256 sample.txt
```

On B, set `HEAD_ID` and `BLOB` to those identifiers. Once the head appears in `archive heads`, resolve it to a new output file and compare its checksum with A's.

```sh
./naome --directory "$NODE_DIR" archive heads
./naome --directory "$NODE_DIR" archive resolve "$HEAD_ID" "$BLOB" received.txt
shasum -a 256 received.txt
```

To exercise reconnection, stop B, publish a second payload and a new snapshot on A, then restart B and resolve the new payload. The catalog exchange recovers releases missed while offline. At the end run `./naome --directory "$NODE_DIR" stop --json` on each node.
