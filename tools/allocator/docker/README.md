# Hosting the membership allocator in Docker (operator runbook)

One container running `rln_gifter_module` on the released `logosctl`, beside
a logos-blockchain node that runs the same way. It keeps **one libp2p PeerId
for its lifetime** (the key is on a volume), publishes the pair testers pin
(`gifter_peer_id`, `gifter_multiaddr`) before the payer is even funded,
re-issues `serve` on every start, and serves up to five auth vectors at once:
**pow-claim** (the verifier reads your node's HTTP API; only when
`POW_NODE_URL` is set), **keycard-attestation** (a Status Keycard attested by
a trusted CA; `KEYCARD_TRUSTED_CAS`) and **eth-allowlist** (addresses from
`allowlist.txt`, re-served on edit), **logos-allowlist** (a tester's
logos-blockchain node key, `allowlist-logos.txt`) and **lez-allowlist** (a LEZ
account id, `allowlist-lez.txt`). The three allowlist vectors are verified by
one module, `rln_auth_module` (bundle `rln-auth-module.lgx`), and
produced on the tester side by one module, `rln_sign_module`
(`rln-sign-module.lgx`).

Written for a macOS Intel host whose node runs through
`logos-blockchain/deployment/compose.run.yml` (API published on `18080/tcp`).
Everything is architecture-neutral: the same files produce a linux-amd64
image there and a linux-arm64 image on an Apple-silicon Mac.

| File | What |
|---|---|
| `build-bundles.sh` | builds the portable `.lgx` bundles this image needs (and the tester producers) inside a `nixos/nix` container on this host → `bundles/` |
| `Dockerfile` | released `logosctl` 0.3.0 + catalog `libp2p_module` 1.1.0 and `liblogos_lez_rln_module` 5.1.0 + `bundles/*.lgx`, installed into a read-only `modules_dir` |
| `entrypoint.sh`, `lib-ctl.sh` | daemon → modules → persisted node key → publish → wallet → serve → supervise |
| `compose.yml` | the service: data volume, port, `host.docker.internal` for the node API, restart policy, capped logs |
| `allocator.env.example` | every knob (incl. `KEYCARD_TRUSTED_CAS`, `ADVERTISE_PORT`, `ALT_MULTIADDRS`, `KAD_BOOTSTRAP_NODES`); copy to `allocator.env` |
| `config/allowlist.txt` | eth-allowlist, one address per line (40 hex, `0x` optional, any case; copy `config/allowlist.txt.example`; the live file is git-ignored); editable while running — the `config/` directory is bind-mounted, so any editor's save is seen |
| `config/allowlist-logos.txt`, `config/allowlist-lez.txt` | logos-allowlist (64-hex public keys, canonical little-endian) and lez-allowlist (64-hex or base58 account ids; the entrypoint decodes base58 and keeps only 32-byte ids), one per line (copy the `*.txt.example`; live files git-ignored); same bind-mount and re-serve behaviour; bad lines are dropped with a log line; `LOGOS_ALLOWLIST=0` / `LEZ_ALLOWLIST=0` turn a vector off; `LOGOS_AUDIENCE` / `LEZ_AUDIENCE` set the verifiers' `audience`. Spec: `docs/auth-allowlists.md` |
| `node/` (`compose.yml`, `node.env.example`, `run-node.sh`) | a FOLLOWER logos-blockchain node on the testers' chain, API on the host loopback: the node the pow-claim verifier reads (§7) |
| `keycard-native.sh` | a real Keycard through a host `logoscore` client against this allocator (§8.1); an operator tool |
| `verify-local.sh` | the D1-D10 end-to-end checks against a local zone (five vectors, restart, re-serve, switch) |
| `node/find-claims.py` | lists PoW reward claims on a node and prints `claim_block_id` + `pow_nullifier` for pinning (§7, §8) |
| `client-compose.yml`, `client-entrypoint.sh`, `client.env.example`, `CLIENT.md` | the CLIENT side in the same image: load the client modules, bring up libp2p, send one request to the allocator and classify the reply — the connectivity probe for a tester machine (see `CLIENT.md`) |
| `delivery-compose.yml`, `client-delivery.sh`, `delivery.env.example` | delivery mode of the client: membership through the gifter, then a delivery node that sends/receives with an RLN proof — `CLIENT.md` §5 |

## 0. Prerequisites on the node machine

```sh
docker compose version                                  # Docker Desktop with compose v2
docker ps --format '{{.Names}}' | grep logos_blockchain # the node is up
lsof -nP -iTCP:9000 -sTCP:LISTEN                        # port 9000 free (else HOST_PORT=<port> docker compose up -d, ADVERTISE_PORT=<port>)
```

pow-claim needs a node on the testers' chain whose API the verifier can read
(`POW_NODE_URL`). If no node runs on this host, or you do not want the
allocator reading the miner's API, run the follower in `node/` (§7). Without
`POW_NODE_URL` the allocator serves eth-allowlist only, which is the
first-contact path for testers anyway.

A copy of this repository (`logos-rln-gifter`) on the machine, for the module
sources and these files. `rln-auth-module.lgx` answers every auth type the
allocator serves, pow-claim included.

## 1. Build the portable bundles (~10 min the first time)

```sh
cd tools/allocator/docker
./build-bundles.sh
ls bundles/      # rln-gifter-module.lgx rln-auth-module.lgx rln-sign-module.lgx
```

The script prints each bundle's variants; they must read `linux-amd64` (Intel)
or `linux-arm64` (Apple silicon), **without** `-dev`. The nix store lives in a
docker volume (`rln-allocator-nix`) so later builds are fast.

## 2. Configure

```sh
cp allocator.env.example allocator.env
cp config/allowlist.txt.example config/allowlist.txt
$EDITOR allocator.env        # ADVERTISE_IP (public IPv4) or ADVERTISE_DNS; ADVERTISE_PORT if HOST_PORT≠9000; payer (optional)
$EDITOR config/allowlist.txt # tester addresses, can stay empty for now
```

Leave `LEZ_RLN_PAYER` / `LEZ_RLN_PAYER_KEY` empty to let the lez module derive
a payer (you fund it in step 4); set both to import a funded key.

## 3. Run

```sh
docker compose up -d --build
docker compose logs -f allocator          # until "serving [...] on /ip4/…"
docker compose exec allocator cat /var/lib/allocator/allocator.json
```

`allocator.json` is the hand-off:

```json
{
  "gifter_peer_id": "16Uiu2HAm…",
  "gifter_multiaddr": "/ip4/<allocator host ip>/tcp/9000",
  "alt_multiaddrs": ["/ip4/192.168.1.10/tcp/9000"],
  "registry_id": "logos:testnet:fd322d32…b971",
  "payer": "<64 hex — fund this>",
  "auth_types": ["logos-pow-claim", "keycard-attestation", "eth-allowlist"],
  "served": true, "funded": false
}
```

Open or forward the host port (9000, or the `HOST_PORT` you ran
`HOST_PORT=<port> docker compose up -d` with; the container always listens on
9000)/tcp on the Mac's firewall and router. The
PeerId is derived from `node_key.hex` on the `allocator-data` volume: the
container, the image and the compose project can all be recreated, the volume
must not. Back it up (the compose project is named after this directory, so the volume
is `docker_allocator-data`; check `docker volume ls` for the volume name):

```sh
docker run --rm -v docker_allocator-data:/d alpine sh -c 'tar czf - /d/node_key.hex /d/wallet-home-* /d/consumed_nullifiers-*.txt' > allocator-backup.tgz
```

If the entrypoint ever reports `PeerId changed`, it refuses to start on
purpose: restore the key rather than re-publishing a new id.

## 4. Fund the payer

There is no faucet. Transfer native balance on the z3 zone to the `payer`
account from any funded account; each registration costs
`rate_limit × price_per_unit` plus the fee reserve (~7.4e7 observed per
registration at rate 100). The log prints the balance on every change and
`payer funded` once it passes `MIN_NATIVE_BALANCE`; `allocator.json` flips
`funded`.

Until then the allocator is fully functional except that every accepted
request ends as `register_member: insufficient_balance: …` (the lez module
refuses before signing; nothing is paid, the credential is released). That is
also the quickest end-to-end probe: a tester can already try and see the
pipeline work up to the chain.

## 5. Add testers

- **eth-allowlist**: a tester sends you the `id` (an address) their
  `rln_sign_module` reports for
  `identity '{"auth_type":"eth-allowlist"}'` (testers doc recipe A); append it to `config/allowlist.txt` and save. The entrypoint re-serves
  within `HEALTH_EVERY_S` (30 s): `docker compose logs --tail 5 allocator`
  shows `re-serving`. Each address yields one membership. The eth signature
  covers only the commitment (wallet compatibility): it binds no rate and no
  allocator, so a leaked payload can be spent at any allocator that
  allowlists the address, at any rate up to that allocator's
  `MAX_RATE_LIMIT`.
- **logos-allowlist**: the tester runs `rln_sign_module.identity` with
  `{"auth_type":"logos-allowlist","args":{"node_url":…}}` against their own node (testers doc recipe D) and sends you the 64-hex key; append it
  to `config/allowlist-logos.txt`. Same re-serve; one membership per key. A
  key that is not a canonical little-endian field element (usually a
  byte-reversed paste) is dropped with a log line. The tester's
  `auth_args.audience` must equal your `LOGOS_AUDIENCE` (both empty by
  default) and their signed `rate_max` (default 100) caps the rate they can
  request.
- **lez-allowlist**: the tester runs `rln_sign_module.identity` with
  `{"auth_type":"lez-allowlist"}` (recipe E) and sends `id_base58` (or the hex
  `id`); append it to `config/allowlist-lez.txt`. The entrypoint decodes
  base58 itself and passes lowercase hex to the verifier; an id that does not
  decode to exactly 32 bytes is dropped with a log line (the verifier would
  reject the whole list for it). `auth_args.audience` must equal your
  `LEZ_AUDIENCE`; the signed `rate_max` caps the rate.
  One membership per account.
- **pow-claim**: nothing to configure per tester. They need a node that mines
  on the chain `POW_NODE_URL` follows and a settled reward claim; the verifier
  checks the claim against that node (§7, §8).
- **keycard-attestation**: nothing to configure per tester. One membership per
  physical card (nullifier = `keccak256` of the card's identity public key);
  the card must be attested by a CA in `KEYCARD_TRUSTED_CAS` (§8.1).

The full tester-side sequence is in `docs/testers-getting-a-membership.md`;
give them that file, `allocator.json`, and the producer bundles from
`bundles/` (linux bundles load only in the Docker client; a native macOS
tester needs darwin builds from you, and `keycard-capture-module` is not
built by `build-bundles.sh`: see §8.1).

A tester who used the earlier `rln_sign_module` keeps their allowlisted
address only by importing that key into the new module:
`logosctl call rln_sign_module import_key '{"auth_type":"eth-allowlist","private_key":"0x…"}'`
(add `"force":true` when the new module already minted a different key; the
old module's key lives in its own persistence directory, which the new
module does not read). Otherwise allowlist the new `id` they report.

## 6. Operate

```sh
docker compose logs -f allocator                 # health lines every 30 s on change only
docker compose exec allocator logosctl --json call liblogos_lez_rln_module wallet_status
docker compose exec allocator logosctl status            # modules loaded
docker compose exec allocator cat /var/lib/allocator/consumed_nullifiers-${REGISTRY_REFERENCE}.txt
docker compose kill -s HUP allocator             # force a re-serve
docker compose restart allocator                 # same PeerId, serve re-issued
docker compose down                              # keeps the volume
```

The wallet homes (`wallet-home-<REGISTRY_REFERENCE>`) and nullifier files
(`consumed_nullifiers-<REGISTRY_REFERENCE>.txt`) are per registry (§10).

Upgrading modules: rebuild the bundles, `docker compose up -d --build`. The
volume (key, wallet, nullifiers) is untouched.

## 7. The follower node for pow-claim (`node/`)

The verifier (`rln_auth_module`) answers four reads per request from
the node at `POW_NODE_URL`: is the claim block final on this node, is it in
the immutable index, what does it contain. The allocator must therefore see
a node on the chain the testers mine. `node/` runs one in Docker, a
**follower**: it never mines, owns nothing, and publishes its API on the
host's loopback only (the node API also serves `/wallet/sign/zk`, an
unauthenticated signer, so never expose it on a LAN address).

```sh
cd node
cp node.env.example node.env
$EDITOR node.env       # NODE_IMAGE_LABEL = the miner's tag; MINER_PEERS; NODE_NET_PORT free
docker compose --env-file node.env up -d
docker compose --env-file node.env logs -f      # "API up; peer …", then sync
curl -s localhost:18080/cryptarchia/info        # phase/state, lib_slot
```

- **Same tag as the miner.** Each release carries its chain's deployment
  built into the module; `run-node.sh` starts with an empty deployment path,
  which uses it. A different tag is a different fork and syncs nothing. To
  pin a file instead, place the miner's `/node-data/deployment.yaml` as
  `node/deployment.yaml` (git-ignored); it is copied in on every start.
- **Peers.** `MINER_PEERS` go into `initial_peers` (also the IBD peer list).
  The chain's bootstrap nodes from the miner's `user_config.yaml` are enough;
  adding the miner itself (`curl -s localhost:18080/network/info` there,
  `/ip4/<its ip>/udp/<swarm port>/quic-v1/p2p/<peer_id>`) is optional.
- **Config.** Generated once by the module (`generate_user_config`) into the
  `rln-allocator-pow-node-data` volume; regenerated (new keys, same chain
  data) when `MINER_PEERS`/`NODE_NET_PORT` change. The generated
  `prolonged_bootstrap_period` of 3600 s is patched to 5 s: during that
  period a node reports `lib_slot 0` and the verifier refuses every claim as
  "not final yet".
- **Ready when** `curl -s localhost:18080/cryptarchia/info` shows
  `"phase":"Following"`, `"state":"Online"` and a `lib_slot` close to the
  miner's. Initial block download of the public testnet (0.3.2, 14k blocks)
  took 3.5 min here. `slot − lib_slot` is the finality lag: 1000 blocks at
  a measured ~41 s per block (1 s slots), about 11 h on that chain, which is
  the wait between a claim and its use.
- The allocator's `POW_NODE_URL=http://host.docker.internal:18080` (set it
  once this node reports Following/Online; it ships empty in
  `allocator.env.example`) reaches it; `NODE_API_PORT` changes
  the host port if 18080 is taken (then change `POW_NODE_URL` too).

## 8. pow-claim end to end (operator side)

Tester procedure: `docs/testers-getting-a-membership.md` recipe B.

Chain numbers (public testnet 0.3.2): 1 s slots, a measured ~41 s per block,
finality = 1000 blocks, about 11 h. The producer's default scan window is
3000 slots, about 50 min after finality, so the tester almost always pins the
claim (`claim_block_id` + `pow_nullifier`, from `node/find-claims.py --tx
<claim tx hash>`); that is the normal path.

- The claim must be on the chain the follower follows (same image tag as
  `node/`, §7).
- The check is independent of `REGISTRY_REFERENCE`: the verifier checks the
  chain, the registry only pays. Nullifiers are per registry, so a claim
  already used on the local zone can be used once more on testnet (§10).
- `GET /pow/rewards/claimable` on the tester's node lists what is still
  unclaimed; unclaimed tickets expire after 300 slots, auto-claim ticks every
  10 s on a generated config.
- Replies: `claim block not final yet (slot s > lib_slot L)` means the
  follower's LIB lags (or is still bootstrapping), retry later;
  `credential already used` means that claim already bought a membership;
  `auth_success:true` with a tx hash means granted.
- `POW_AUDIENCE` (currently empty) must equal the `audience` in the tester's
  `auth_args`.

Verified runs: see the Verification log.

## 8.1 keycard-attestation (Status Keycard)

The verifier `rln_auth_module` (bundle `rln-auth-module.lgx`, built by
`build-bundles.sh` by default) needs no PC/SC and no card on the allocator
host. `KEYCARD_TRUSTED_CAS` is a comma-separated list of 33-byte compressed
secp256k1 CA public keys (hex): empty = the Status production CA
`029ab99ee1e7a71bdf45b3f9c58c99866ff1294d2c1e304e228a86e10c3343501c` only;
`none` = the vector is not served. A test CA may be appended **only on a local
zone**, for `verify-local.sh` D8, and must be removed before public exposure;
the entrypoint logs a WARNING while a non-production CA is trusted.

Nullifier = `keccak256` of the card's identity public key: one membership per
physical card, and it survives a factory reset.

Operator notes (tester procedure: recipe C in the testers doc):

`keycard-native.sh` is an operator tool. It needs this repo checkout, a
nix-built `logoscore` and a card in a PC/SC reader on the machine; it uses the
`verify-local.sh` client harness plus `keycard_capture_module`, waits for a
card, sends one request to the allocator named in `allocator.json` (or
`ALLOCATOR_PEER_ID` / `ALLOCATOR_MULTIADDR`), then a replay. For a remote
allocator set `ALLOCATOR_PEER_ID` and `ALLOCATOR_MULTIADDR`.

`keycard_capture_module` is a producer needing PC/SC and a card on the machine
running `logosctl` natively (the client container cannot reach a reader); it is
NOT built by `build-bundles.sh`. A native macOS tester needs a darwin build,
which you produce with `nix build ./rust/keycard-capture-module#lgx` and send.

Without a card, `verify-local.sh` D8 sends a synthetic attestation from
`tools/mint_attest.py` through the client probe (`CLIENT_AUTH_PAYLOAD`,
`CLIENT_IDENTITY_COMMITMENT`, `CLIENT.md`): refused with an untrusted CA,
granted with the test CA, replay refused. D1 asserts the third vector.

## 9. Public exposure

Testers need TCP 9000 (or your `HOST_PORT`) reachable at a stable address.
Options:

- A public IP with a port forward: set `ADVERTISE_IP` (or `ADVERTISE_DNS`,
  with dynamic DNS if the IP changes) and `ADVERTISE_PORT`.
- A small VPS forwarding TCP to the host: advertise the VPS address.

```sh
ADVERTISE_IP=<stable ip>               # gifter_multiaddr
ADVERTISE_PORT=9000                    # the port testers dial
ALT_MULTIADDRS=/ip4/<LAN ip>/tcp/9000  # optional; also published in the DHT advertisement
KAD_BOOTSTRAP_NODES=<multiaddr>/p2p/<peerId>,…   # DHT peers; empty = reachable by pinned peer id only
```

With `KAD_BOOTSTRAP_NODES` set the entrypoint creates the libp2p node with
`mountKad:true`, `mountServiceDiscovery:true` and those peers as
`bootstrapNodes`, and `serve` gets `advertise:true` and
`advertiseAddrs:[ADVERTISE_ADDR, ALT_MULTIADDRS…]`: a client finds the
allocator by registry through the DHT and dials those addresses
(`docs/running-an-allocator.md` §2.5).

Then `docker compose up -d` (same PeerId). `ADVERTISE_PORT` defaults to 9000
(set it to `HOST_PORT` when that differs). LAN testers can dial
`alt_multiaddrs`. Keep the host awake and reachable: set Docker Desktop to
start at login and disable sleep on AC (`sudo pmset -c sleep 0`). The host's
LAN address may change (DHCP): advertise a stable one.

Traps: libp2p's dial is plaintext (multistream-select), so the advertised
port must forward raw TCP to the allocator. nim-libp2p ignores `/etc/hosts`
and resolves IPv4 only, so multiaddrs dialled from the client container must
be `/ip4/…`.

## 10. Switching registry (local ↔ testnet)

An env flip of three values in `allocator.env`:

| | local | testnet |
|---|---|---|
| `REGISTRY_REFERENCE` | `local` | `testnet` |
| `REGISTRY_CONFIG` | `7bd1e28e47b1e50f96d806ed96e4214c762ab2b639a9bed2b45dede16099d4db` | `fd322d32a46ddf57eece9db8d68e9b722262d1f770760fca63b8cb9e7775b971` |
| `LEZ_RLN_SEQUENCER` | `http://host.docker.internal:3040/` | `https://testnet.lez.logos.co/` |

`LEZ_RLN_PAYER*` stay empty: never carry a local genesis key across.

```sh
docker compose up -d      # recreates on the same volume: same PeerId
docker compose logs -f allocator      # wait for: serving … logos:testnet:…
docker compose exec allocator cat /var/lib/allocator/allocator.json
```

`allocator.json` must show `registry_id` `logos:testnet:fd32…` and the
testnet payer from `wallet-home-testnet/`; a different payer means the wallet
home was lost. Until that payer is funded by transfer (§4) every request ends
`insufficient_balance`. Flip back the same way.

- The wallet home and the nullifier file are per registry: a credential spent
  on local can be spent again on testnet.
- `allocator.json` is rewritten, so testers pinned to the other registry sit
  `pending`.
- `MIN_NATIVE_BALANCE` is informational: serve never waits. `funded` latches
  true once per start when balance >= MIN; MIN=0 never flips it.

Drill (2026-10-16, this Mac): local → testnet took 32 s to `serve` (wallet
`ready` with the existing testnet payer `b17b02af…4404`, `registry_id`
`logos:testnet:fd32…`, `funded:false`); a probe answered
`insufficient_balance: payer … holds 0, a registration needs 91900000`;
testnet → local took 2 s and the next probe hit the local registry again. 38 s
end to end, same PeerId throughout, no other env line changed.

## Verification log

Oldest first.

### 2026-10-15, Apple-silicon Mac, linux-arm64 image, hosted testnet z3

`verify-local.sh` against this compose: modules load from the portable
bundles under the released `logosctl`; `allocator.json` is published before
the wallet is ready; the PeerId survives `docker compose restart` and a
`logosctl daemon stop` inside the container (both re-serve); an allowlist
edit re-serves within 30 s; an eth-allowlist request from a host client is
accepted by the verifier and refused by the registry module only for
`insufficient_balance` (nothing paid, nothing persisted); a pow-claim
request is routed by vector name. Wallet bring-up against the hosted
sequencer took ~75 s on a fresh volume and ~5 s afterwards.

Trap found on the way: **`libp2p_module.peerInfo` is unreliable once the
gifter has mounted its protocol** (from a second client 4 of 6 calls failed
or timed out at 20 s). The entrypoint reads the PeerId before `serve` and
probes liveness with a TCP connect, never with `peerInfo`; do the same from
`exec`.

### 2026-10-16, Intel Mac, pow-claim (§8)

Two real testnet tickets mined on an Intel Mac, pinned (`find-claims.py --tx
…`), both granted memberships on a local zone through the client container
(verify 29-60 ms, 74,142,108 paid each). With the chain's finality of ~11 h
the scan window had passed, so pinning from the start is the normal path.

### 2026-10-16, Apple-silicon Mac, linux-arm64 image, local zone, three vectors

`verify-local.sh` D1-D8 ALL PASS with `keycard-attestation` served beside
pow-claim and eth-allowlist: D6 granted an eth-allowlist membership on the
local zone; D8a (attestation under an untrusted CA) was refused `attestation
CA is not trusted`, D8b (fresh synthetic card under the test CA) was granted
in 5 s, D8c (same card, new commitment) was refused `credential already used:
keycard-attestation:<keccak(ident_pub)>`. The test CA was then removed and
the container recreated: `serve.json` trusts only the production CA, no
WARNING in the log. Trap: a `/dns4/host.docker.internal/…` multiaddr does
not resolve inside the client container (nim-libp2p's resolver does not read
`/etc/hosts`); D8 dials the host gateway's IPv4 instead.

### 2026-10-16, real Keycard (§8.1)

`keycard-native.sh` with a real Status Keycard in an ACS ACR39U reader on
this Mac: `card_status` `{"present":true}`, grant (leaf 9 on the local zone)
in 9 s, replay refused `credential already used:
keycard-attestation:<keccak(ident_pub)>`. Trap: the reader was powered
(blinking) but not enumerated behind a hub until re-plugged;
`SCardListReaders` (or `card_status`) is the check, not the LED.

### 2026-10-16, public path (§9)

Client container dialled the allocator from a machine on another network (an
Intel Mac on a second network) and got a real gifter reply after 2 s
(`credential already used`), exit 0, twice in a row.

### 2026-10-16 — first grant on the hosted testnet (z3)

Registry flipped to testnet (README §10), payer `b17b02af…4404` funded with
500,000,000, `funded` flipped within 30 s. A probe from the client container
on this host (pinned eth-allowlist key, fresh nullifier on this registry)
answered **nothing at 19 s**: logosctl's call deadline is shorter than a
testnet registration. The grant had landed by 90 s (nullifier
`eth-allowlist:0x17c5…` in `consumed_nullifiers-testnet.txt`, payer paid
74,161,352), and a re-send was refused `credential already used`. The probe
client now does that re-send itself after `CLIENT_CONFIRM_WAIT_S` (120 s)
and reports the first attempt as granted. The asynchronous
`register_membership` path testers use is not affected by the CLI deadline.

### 2026-10-16 — Intel Mac client, public internet, hosted testnet

From the Intel Mac on a second network, against the allocator on z3: eth-allowlist
(allowlisted key `0x85a6…`) and pow-claim (pinned claim 2, its own node at
`http://host.docker.internal:8080`) each answered nothing at ~20 s and were
reported `GRANTED on the first attempt` by the probe's re-send 120 s later.
Allocator side: payer balance 425,838,648 → 351,654,432 → 277,457,728 (two
registrations of ~74.2M each), both nullifiers in
`consumed_nullifiers-testnet.txt`, the pow verifier accepted in 21–28 ms
against the follower (`lib_slot` 613838). The registry's
`total_registrations` reads 9 (it counts every allocator on z3). The probe's
commitments are random, so these memberships have no usable secret; a real
tester goes through `register_membership`, which derives the commitment
from its own identity. Claim 1 of the Intel Mac is still unspent on testnet.

### 2026-10-16/17 — delivery on gifted memberships (Run 1, `logos.test`, hosted testnet)

Both delivery nodes obtained their RLN membership THROUGH the allocator
(`CLIENT_MODE=delivery`, `liblogos_rln_module.register_membership` delegated
to the gifter) and the sender used it on the public `logos.test` fleet:

| | Node B (this Mac, receiver) | Node A (Intel Mac, sender, second network) |
|---|---|---|
| credential | eth-allowlist, fresh key `0x5a42…`, direct dial | pow-claim, pinned claim 1, from a machine on another network |
| wallet ready | 127 s | 169 s |
| `register_membership` → `active` | 22 s, leaf 9 | 34 s, leaf 10 |
| delivery | Ready, Connected 1 s after subscribing | Ready, Connected |
| payer paid | 74,151,904 | 74,193,288 (balance now 129,112,536) |

A sent `hello from the Intel Mac on a gifted membership #1 …`:
`dispatchRlnGenerateProofRequestEvent` then `messagePropagated`, quota
100→99 on leaf 10, no `messageError`, ~2 s after `send`. B logged
`RECEIVED` for the same hash `0x503529e9…d5ce`, source `live`, payload
intact. The shipped `logos.test` preset does not validate proofs, so this
run shows the gifted membership was obtained and spent on a proof, and the
message crossed the fleet; Run 1b (`DELIVERY_VALIDATE=1` on B) adds the
validation.

### 2026-10-18 — logos-allowlist and lez-allowlist on a fresh local zone

Image rebuilt with the four new bundles (`logos_auth_module`,
`logos_sign_module`, `lez_auth_module`, `lez_sign_module`; all ten
`linux-arm64`), allocator on a freshly provisioned local zone (wallet ready
in seconds; a wallet home left over from an older chain had needed many
minutes to replay, so the zone was reset and `wallet-home-local` removed).
`verify-local.sh` D1–D10 ALL PASS (D8 skipped: test CA not trusted):
- D9 (logos): the client container's `logos_sign_module` took the key from
  the follower node (`/pow/status`, K `e2c2755d…ea08`), the empty list
  answered `allowlist is empty`, after allowlisting K the request was
  **granted** (verifier offline against the vendored VK, reply in 2 s),
  the replay was refused `credential already used: logos-allowlist:<K>`.
- D10 (lez): a module key's base58 account id was refused on the empty
  list, granted once allowlisted, replay-refused, and a second key listed
  by its 64-hex id was granted too.
The allocator paid ~74M per grant from the zone's genesis-funded payer.

### 2026-10-18 — consolidated allowlist modules

`rln_auth_module` (one verifier for `eth-allowlist`, `logos-allowlist`,
`lez-allowlist`) and `rln_sign_module` (one producer: `produce_auth`,
`identity`, `import_key`) replaced the six separate modules. Rebuilt image,
`verify-local.sh` D1–D10 ALL PASS on the local zone (eth grant, logos
through the follower node answered `credential already used` for the key
spent by the earlier run, lez grants by base58 and by hex, replay refused),
`verify-chainless.sh` A1–A12 ALL PASS with all three types served by the
single verifier instance. Trap: in the chainless script a nested
`al_field "$(al_call … | al_res)" id` dropped the logos `identity` reply;
capturing the envelope in a variable first works (kept, with the reply
dumped to `runs/<ts>/a11a.env.json`).

## What is still manual / not covered

- Funding and keeping the payer topped up; the balance is logged, not alerted.
- Firewall, NAT and DNS.
- `maxRateLimit` is a flat cap (100 by default): the gifter clamps silently and
  the requester's RLN module reports a `rate_limit_mismatch` if it asked for
  more. The membership UI asks for 100.
- One registry per allocator; a tester naming another registry sits `pending`
  and fails after the confirmation window.
