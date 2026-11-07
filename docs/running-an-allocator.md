# Running your own RLN membership allocator

Internal reference for agents and engineers working on the membership
allocation protocol ([LIP-158], `/logos/rln/membership/1.0.0`). It answers
three questions from the current code, not from the design we want:

1. What is an "allocator" (gifter) concretely, and what does it take to stand
   one up for your own application's users?
2. How does an application plug in its own validator (auth vector)?
3. How does a user's RLN module obtain a membership from that allocator instead
   of paying from its own wallet?

Section 7 maps the three longer-term goals onto what exists and what is
missing. Everything else is a description of today's behaviour with
`path:line` pointers so a reader can re-verify.

**Revisions described** (all local checkouts under `/Users/arseniy/Waku/Logos/`):

| Checkout | Rev | Role |
|---|---|---|
| `logos-rln-gifter` (this repo) | `01dd6f8`, branch `fix/register-target-lez-rln-module`; `eth-sign-module` added uncommitted on `feat/eth-sign-module` (2026-10-12) | gifter module, vector kit, reference vectors |
| `logos-rln-modules` | `1adf114`; membership UI 0.8.0 uncommitted on `feat/membership-ui-0.8.0` off `feat/intents` (rln 0.12.0, 2026-10-12) | `liblogos_rln_module` (membership, the client), `liblogos_lez_rln_module` (registry provider, chain + payer wallet), membership UI |
| `logos-libp2p-module-master` | `7b4b776` | `libp2p_module` (transport, identity key) |
| `logos-rln-e2e` | `20c11be` | scenarios `consumer-gifter`, `chat-basecamp-gifter`, quarantined `mix` |
| `logos-lez-rln` | `379226e` | chain programs and layouts |
| `logos-lips` | `6ebd9c86` | LIP-158, membership-management spec |

Since 2026-11-05 (gifter 0.4.0, rln_auth_module 0.2.0, rln_sign_module
0.2.0, shared crates auth-crates-v0.3.0, liblogos_rln_module 0.14.3,
libp2p_module 1.1.0): a gifter serves several registries and the request
names one (§1.2, §3.1); spent credentials are keyed per registry; the
verifier sees the requester's transport peer id, which the `peer` scheme
(`peer-any`, `peer-allowlist`) judges (§4.3). Sections below that cite
`server.rs:<line>` predate that change.

Since 2026-11-06 (gifter 0.5.0, liblogos_rln_module 0.15.0,
logos-delivery-module 0.3.6): the allocator advertises what it serves
through libp2p service discovery and a client finds it without a configured
peer id; the configured pair is the fallback (§2.5).

Not covered here: how to write a vector module (read
`crates/rln-auth-vector/README.md`), RLN proof generation, chain internals.
Paths below are relative to the checkout named in each section; this repo's
paths have no prefix.

---

## 1. What an allocator is today

### 1.1 Not a binary: four modules in a logoscore daemon

There is no gifter executable, config file or CLI. An allocator is an ordinary
`logoscore` daemon with these modules loaded, in this order:

| Module | Why it is there | Load-order constraint |
|---|---|---|
| `libp2p_module` | transport; owns the node identity key, listens, mounts the protocol | before `rln_gifter_module`: its `on_context_ready` opens clients to libp2p and the registry module (`rust/rln-gifter-module/rust-lib/src/lib.rs:80-82`, `lp.rs:29-30`) |
| `liblogos_lez_rln_module` | registry provider: in-process wallet, the payer key, `register_member`, `get_membership`, `get_registry_bounds` | before `serve` is called; a missing one is not detected until the first request (~190 s stall, see §4.4) |
| `rln_gifter_module` | the protocol: `serve` (server half) and `request` (client half) in one module | — |
| zero or more verifier modules | the pluggable validator (§4) | before `serve`: `serve` opens a client to each named verifier on the owner thread (`server.rs:97-100`) |

Since 2026-11-05 the gifter module declares `libp2p_module` as a
`metadata.json` dependency (logoscore loads it first; a node without the
libp2p bundle does not load the gifter), and `liblogos_rln_module` 0.14.4
declares the gifter the same way, so loading the membership module brings the
allocator client and libp2p with it. The registry module and the verifier /
producer modules stay undeclared on purpose: their cross-module clients are
created lazily so a deployment missing, say, a producer module still loads
(`lp.rs`).

The e2e bring-up that does exactly this is
`logos-rln-e2e/scenarios/consumer-gifter/run.sh:98-135`:
`daemon_self_paying` → `daemon_start` → `daemon_load_modules n1
liblogos_lez_rln_module liblogos_rln_module libp2p_module rln_gifter_module` →
wallet open/sync → fund the payer → `createNode` + `start` → `peerInfo` →
`serve`. (`liblogos_rln_module` is loaded there only because the harness shares
a module set with the client node; a pure allocator does not need it.)

### 1.2 Configuration is one runtime call

The whole server configuration is the JSON argument of `rln_gifter_module.serve`
(`server.rs:70-131`). Nothing is persisted: after every daemon restart `serve`
must be called again, by whatever supervises the daemon.

| Key | Required | Default | Meaning |
|---|---|---|---|
| `config` | yes | — | the registry's ConfigState account (64-hex or base58; canonicalised to lowercase hex). The registry a request naming none is served on. |
| `registries` | no | — | further served registries: `["<config>", {"config": "<config>", "maxRateLimit"?: N}]`; an entry without a cap takes the global one. A request names its registry on the wire (request field 100; the membership module sends its scope's); one not served is refused `registry not served: <cfg>` before any verifier runs (§3.1). The `serve` reply lists them. |
| `wallet` | yes | — | the payer account id. Must be a key the registry module's wallet holds. `""` means "the registry module's own payer" (`liblogos_lez_rln_module.lidl:60-68`, `logos-rln-modules`). |
| `authVerifiers` | no | absent = **open gifter** | `{"<auth_type>": {"module": "<logos module>", "config"?: {...}}}`. Present-but-malformed fails `serve` rather than degrading to open (`server.rs:85-106`). |
| `consumedNullifiersPath` | no | `""` = replay protection in memory only | append-only file, one lowercase `<registry>:<type>:<nullifier>` per line (`auth.rs:10-41`); a credential buys one membership per registry. Without it a restart forgets every spent credential. |
| `maxRateLimit` | no | `100` (`DEFAULT_MAX_RATE`, `server.rs:39`) | requests above it are clamped, silently. A request with no rate gets this value. Per registry when the `registries` entry sets its own. |
| `advertise` | no | `true` | publish the served (registry, auth type) pairs through libp2p service discovery (§2.5). Left to the default, a node without discovery mounted serves unadvertised and the reply carries `advertiseError`; an explicit `true` makes that fail `serve`. `false` serves unadvertised. At most 8 pairs fit one advertisement. The reply carries `advertised`, `serviceId`, `serviceData`. |

Re-calling `serve` refreshes the configuration (new wallet, new verifier set).
The protocol is mounted and the worker spawned only once; the consumed
nullifier set is merged, never replaced (`server.rs:108-129`); an
advertisement whose data changed is stopped and started again — by the
worker between two accepts once it runs (the reply says `advertisePending`),
because `protocolAcceptStream` blocks libp2p_module's call dispatcher and
the module answers nobody else while one is pending (see §4.4).

Fixed constants an operator should know (`server.rs:24-40`, `wire.rs:8`):

| Constant | Value | Effect |
|---|---|---|
| protocol id | `/logos/rln/membership/1.0.0` | not configurable |
| `MAX_RPC_SIZE` | 4096 B | request size cap |
| `READ_TIMEOUT_MS` | 60 s | client must send within this after opening the stream |
| `AUTH_VERIFY_TIMEOUT_MS` | 30 s | budget for the verifier module call |
| `REGISTER_TIMEOUT_MS` | 190 s | budget for `register_member` |
| `CONFIRM_BUDGET` / `CONFIRM_POLL` | 150 s / 2 s | how long to wait for the registry to show the leaf |
| worker | one serialized thread | one registration in flight at a time, so the payer's nonces stay ordered (`server.rs:133-156`). Throughput is roughly one registration per block. No per-peer limit, no queue cap. |

### 1.3 Request lifecycle on the server

```
client                                   gifter daemon
  |  protocolRequest ------------------>  protocolAcceptStream (libp2p_module)
  |  RlnGifterRequest {                    |
  |    request_id, authentication_type,    |  1. decode; commitment must be 32 B
  |    authentication_payload,             |  2. registry = field 100 || config; must be served
  |    identity_commitment, rate_limit?,   |  3. settle rate = min(requested||100, that registry's maxRateLimit)
  |    config_account_id? (100) }          |  4. if authVerifiers: look up type -> verify_auth (+ the stream's peer id)
  |                                        |     nullifier? -> reserve <registry>:<type>:<nul> (reject if spent), persisted at once
  |                                        |  5. liblogos_lez_rln_module.register_member(registry, wallet, idc, rate)
  |                                        |  6. poll get_membership(registry, idc) until registered:true and usable (<=150 s)
  |  RlnGifterResponse {         <-------  |  7. reply with the chain's leaf_index
  |    leaf_index, transaction_hash,       |
  |    config_account_id (field 100) }     |
```

Step 1 checks only the length. A 32-byte value that is not a valid BN254
scalar (the registry reads it **little-endian**, so the last byte must leave
the value below the field modulus) passes the gifter. On lez module 5.0.0
`register_member` passed it on too, the guest program panicked on chain
(`Input is not a valid BN254 field element`), the transaction was charged in
full, and the lez module's register watcher read the revert as stale claims
and re-sent five more times — measured by the e2e agent at ~4.8e8 native
per bad commitment against ~7.4e7 for a real registration (§7, Goal A).
Closed on the lez side in 5.1.0 (`logos-rln-modules` branch
`feat/check-registry`, commit `5ac03c4` "refuse a registration the program
would reject, before signing"): `register_member` now answers
`{"error":"invalid_commitment: …"}` without submitting, which the gifter
reports as `register_member: …` (NotSubmitted, nullifier released). Since
2026-10-14 the gifter checks the same rule at BOTH ends
(`wire::commitment_refusal`: 32 bytes, non-zero, little-endian value < r):
`request` refuses before any producer call or dial, and `serve` refuses on
arrival before the verifier is consulted, both with the lez module's own
`invalid_commitment: …` wording. Three independent refusals, no chain
round-trip for a bad commitment.

Steps 1–3: `server.rs:195-305`. Steps 4–6: `register()` at `server.rs:369-424`
(introduced by commit `01dd6f8`: `register_member`'s own leaf is a pre-submit
estimate, so the leaf is read back from the chain).

Failure semantics for an authenticated credential (`server.rs`,
`handle_request`): the reservation is written to the nullifier file the
moment it is taken, so a gifter restarted during the <=150 s confirmation
wait cannot grant the same credential a second membership.

- nothing was submitted (`NotSubmitted`: the registry module refused,
  `send_failed`, a transport error, an expired membership already on the
  commitment): the reservation is released, in memory and in the file, and
  the credential can be used again. The reply's failure message starts with
  `not submitted: `, which tells the client it may ask the next allocator.
- submitted but not on chain within 150 s (`Unconfirmed`): the reservation
  stays; the reply starts with `unconfirmed: ` and says "it may still land",
  and the client stops there. The client's own registry poller will usually
  still see it go active (§5.3).
- a crash between the reservation and a `NotSubmitted` verdict leaves the
  credential spent: the operator removes its line from the file.
- a spent credential presented again WITH the same commitment (a retry after
  a reply the client never read) is answered with the membership that
  commitment holds, when the registry shows it usable; nothing new is spent.
  With another commitment it is a replay and refused.
- a re-`serve` naming another `consumedNullifiersPath` carries the spent set
  into the new file first.

Spec deviations to be aware of: `merkle_root` is always empty and
`block_number` always 0 (`server.rs:406-409`); `config_account_id` rides in a
non-spec protobuf field 100 (`wire.rs:25`).

---

## 2. The libp2p PeerId is the trust anchor

This is the one part of the deployment that is easy to get wrong and expensive
to change later.

### 2.1 What the PeerId does

A client dials a `(peer id, multiaddr)` pair — one it discovered (§2.5) or
the configured one: `rln_gifter_module.request` passes
`{"peerId", "multiaddrs":[addr], "proto": "/logos/rln/membership/1.0.0"}` to
`libp2p_module.protocolRequest` (`client.rs`, `ask`), which does
`connectPeer(peerId, multiaddrs)` then `dial(peerId, proto)`
(`logos-libp2p-module-master/src/protocol_bridge.cpp:72-78`).

The **only** authentication of the gifter is libp2p's secure-channel handshake
proving the remote holds the key behind that PeerId. The reply is checked for
nothing beyond `request_id` equality (`client.rs:117`): the client does not
verify `transaction_hash`, `leaf_index` or `config_account_id`. It does not
need to, because confirmation comes from the client's own registry read (§5.3).
So a wrong PeerId cannot steal a membership, but it can make the client send
its commitment to a stranger, wait 300 s and fail.

Consequences:

- **A configured PeerId is a deployment artifact.** A client configuration
  that pins one embeds it; if it changes, every such client must be
  re-pointed. It must therefore come from a **persisted identity key**, never
  from a fresh key per start. A discovered allocator carries its current peer
  id and addresses in its signed record, so discovery alone survives a key
  change.
- **A configured pair travels out of band** with a routable multiaddr. There
  is no `/p2p/<id>` suffix convention in the current callers; the two values
  are separate fields everywhere (`gifter_peer_id`, `gifter_multiaddr`).
- **Linkability.** The gifter learns `(client PeerId, client IP,
  identity_commitment)`. LIP-158 declares this out of scope and points at
  stealth commitments as future work (`rln-membership-service.md`,
  Motivation). An application whose users care about unlinkability should
  know the allocator operator sees this.

### 2.2 How the identity key is set and read

All in `libp2p_module` (`logos-libp2p-module-master`), nothing in the gifter:

| Action | How | Where |
|---|---|---|
| mint a key | `logoscore call libp2p_module newPrivateKey` → hex | `src/plugin.cpp:308` |
| use it | `createNode '{"privKey":"<hex>","addrs":[...]}'`, or the `LIBP2P_MODULE_CONFIG` env var (inline JSON or a file path) before load | `README.md:17-45`, `config.example.json` |
| omit it | a fresh key, and a fresh PeerId, every `createContext` | `src/plugin.cpp:150-159` |
| read the PeerId | `peerInfo` → `{peerId, addrs}`; `getNodeInfo PeerId`; `getNodeInfo Multiaddrs` | `README.md:71-76` |

Relevant `createNode` keys for an allocator: `privKey`, `addrs`, `transport`,
`maxConnections`/`maxInConnections`/`maxOutConnections`/`maxConnsPerPeer`,
`mountGossipsub:false`, `mountKad:false`, `mountServiceDiscovery:false`
(the allocator needs none of the mesh).

### 2.3 How the existing deployments handle it

| Deployment | Key | PeerId stability | Address |
|---|---|---|---|
| e2e `consumer-gifter`, `chat-basecamp-gifter` | none (`createNode {"addrs":[...]}` only) | new every run; read back from `peerInfo` into a shell variable | `/ip4/127.0.0.1/tcp/61871` (`E2E_GIFTER_PORT`), hand-built, loopback only (`consumer-gifter/run.sh:115-123`) |
| `tools/allocator/run-allocator.sh` | `$ALLOCATOR_HOME/node_key.hex`, minted once, passed as `privKey` on every `up` | stable; asserted unchanged against `allocator.json` on a re-`up` | `LISTEN_ADDR` bound, `ADVERTISE_ADDR` published (required when binding `0.0.0.0`) |
| membership UI (0.8.0) | — | no default: the user pastes the allocator's published peer id (0.7.4 hardcoded a deleted local demo's id) | pasted alongside |
| quarantined `mix` | none; `docker compose restart` resets the PeerId and the scenario re-reads it and re-mounts (`scenarios/mix/orchestrate.sh:654-669`) | per container start | `/ip4/<container-ip>/tcp/9000` |

No current e2e scenario exercises a persisted key or a non-loopback address.

### 2.4 Addressing traps

Binding `0.0.0.0` makes libp2p advertise `127.0.0.1`; in the containerised
`mix` topology that produced a Noise peer-id mismatch and dropped connections.
The fix was to bind and advertise the routable interface address explicitly
(`logos-rln-e2e/harness/container/entrypoint.sh:10-22`). For a public
allocator: listen on the routable IP (or bind `0.0.0.0` and publish the
external address yourself), and publish exactly the multiaddr clients should
dial.

**`createNode` falls back silently.** When it rejects part of its config it
reports `success:true` and builds the node from defaults: fresh key, random
port. Observed by the e2e agent on upstream `libp2p_module` 1.0.0 with a
`privKey` of `"null"`, which surfaced only as a client dial failure much later.
Mitigation: after `start`, read `peerInfo` back and assert both that `peerId`
equals the one derived from the persisted key on the previous run and that
`addrs` contains the configured listen address. `tools/allocator/run-allocator.sh` writes
both into `allocator.json`; the e2e scenario asserts them.

**`newPrivateKey` is not reliable across builds.** On the fork build this
repo's tooling uses (`logos-libp2p-module-master` at `7b4b776`) it answers a
hex key before `createNode`; on upstream 1.0.0 as exported by
logos-delivery-module's flake it answered `{"success":false,"value":null}`.
The key format is plain: the protobuf `PrivateKey` envelope
`08 02 12 20 || 32 random bytes` (type Secp256k1), 72 hex chars, so an
operator can mint it with any CSPRNG and skip the module call.

**Hosted in Docker (2026-10-15):** `tools/allocator/docker/` binds
`/ip4/0.0.0.0/tcp/<LISTEN_PORT>` inside the container (the port assertion
matches on the port, since a wildcard bind is reported per interface) and
publishes `ADVERTISE_IP`/`ADVERTISE_DNS` in `allocator.json`; the node key
lives on the `allocator-data` volume and the entrypoint refuses to start if
the PeerId it derives differs from the published one. Testers dial the
host's public address; the Noise handshake binds the PeerId, not the IP.

### 2.5 Discovery (since 0.5.0)

`serve` advertises the node through `libp2p_module`'s service discovery
(the kademlia-based Logos capability discovery, `discoStartAdvertising`)
under the protocol id as the service id, `/logos/rln/membership/1.0.0`
(LIP-158 Appendix A's `/rln/membership/<version>` shape). What it serves
rides in the advertisement's data (`wire.rs`, `service_data`): the byte
`'1'` (layout version) followed by the base64 (no padding) of the sorted
3-byte sha256 prefixes of `<registry canonical hex>/<auth_type>` for every
served (registry, auth type) pair — an open gifter lists `<registry>/` —
at most 8 pairs (libp2p caps service data at 33 bytes; `serve` refuses more).

One advertisement per node, not one per pair, because nim-libp2p's registrar
scores a second advertisement from an IP already in its cache as fully
similar (its Sybil defence) and makes it wait a whole advertisement
lifetime (900 s); two ads from one node then alternate at every renewal.
Appendix A's per-method ids (`/rln/membership/<version>/<auth_method>`) are
therefore not used; the LIP should say so.

A client (`request` with `discover`, default true, or `discover` on its
own) registers interest in the id, looks it up at once and after 2, 4 and
8 s until a record names its pair, keeps the records whose data lists the
pair's digest, and tries the candidates in turn — rotated by the
commitment so clients spread over several allocators — while none has read
the request: a dial or write failure, or a refusal before registration
(`auth_success=false`: registry not served, unsupported or rejected vector,
spent credential) moves on; anything after the request was read (a read
failure, a registration that failed or is unconfirmed, a grant on another
registry) stops. The configured `gifterPeerId`/`gifterMultiaddr` pair, if
any, is tried after the discovered ones; `discover:false` dials it alone.
The reply names who granted (`gifterPeerId`, `discovered`).

What both sides need: `libp2p_module` created with
`mountServiceDiscovery: true` and `bootstrapNodes` naming a reachable
registrar (the delivery module passes the node's plugin-discovery
bootstrap peers). An allocator registers its advertisement with the peers
in its routing table at serve time and otherwise waits for the 10-minute
maintenance heartbeat, so bring the allocator up bootstrapped, then serve.
A node without discovery mounted serves unadvertised (`advertiseError`)
and a client there reports `discovery unavailable` and goes on to the
configured pair. Both the allocator's data and a record's data are plain
text on the module wire; lookups return the data base64-encoded.

Not implemented: a client-side list of pinned gifters (one configured pair
per call), and retrying a candidate that read the request.

---

## 3. Chain side: registry, payer, funding

### 3.1 Registries: the request names one, the gifter serves several

`config` names the default registry and `registries` the further ones
(§1.2). The request carries the registry it wants in field 100
(`config_account_id`, beside the spec like the reply's); the membership
module fills it with its scope's registry (`register_membership`'s
`logos:<ref>:<config-hex>`), and `rln_gifter_module.request` takes it as
`config`. The gifter resolves it first: one it does not serve is refused
`registry not served: <cfg>` with no verifier call and nothing paid; a
request naming none is served on `config`. Spent credentials are keyed per
registry, so one credential buys one membership on each served registry.

The grant names the registry it landed on (`config_account_id`), and both
the gifter client and the membership module compare it with what they
asked for: a grant elsewhere is `gifter registered on <x>, not the
requested <y>` / `failed_reason = "gifter_failed: registered on <x>, not
<y>"` at once, not a `confirmation_window_elapsed` after 300 s. Before
2026-11-05 none of this existed: one gifter served one registry, the wire
carried none, and the e2e `rln-allocator` scenario pinned the silent 306 s
failure; it now pins the refusal.

### 3.2 Who pays and what

`register_member(config_account_id, payer_account_id, id_commitment_hex,
rate_limit)` (`liblogos_lez_rln_module.lidl:60`). The payer "signs the tx,
pays `rate_limit × price_per_unit` of NATIVE balance to the treasury, and pays
the fee" (`lidl:20-27`). The gifter passes `serve`'s `wallet` as the payer
(`server.rs:378-384`).

Nothing on chain records that a membership was gifted. `MembershipState` is
`{rate_limit, id_commitment, grace_period_start_timestamp_ms,
active_duration_sec, grace_period_duration_sec}`
(`logos-lez-rln/lez-rln/rln-layouts/src/state.rs:53-60`): no payer, sponsor or
tier. The only trace is which account signed the Register transaction.
`chat-basecamp-gifter` proves payment by balance deltas: gifter payer drops by
at least `rate_limit × price_per_unit`, client payer stays at 0
(`scenarios/chat-basecamp-gifter/run.sh:419-437`).

### 3.3 Funding the payer

- The registry is native-asset only since `liblogos_lez_rln_module` 4.0.0; the
  faucet and token methods are gone (`lidl:20-27`). Native balance "enters an
  account only at genesis, over the bridge, or by transfer from something
  already funded" (`logos-lez-rln-module/README.md:100-107`).
- The module's wallet derives a payer of its own when no `LEZ_RLN_PAYER` is
  set; it is published through `wallet_status` and must then be funded by
  someone (`logos-rln-e2e/harness/lib/daemon.sh:148-158`). Alternatively
  `LEZ_RLN_PAYER_KEY` imports one funded key, or `LEE_WALLET_HOME_DIR` adopts a
  staged wallet home.
- The e2e harness funds it with lez-rln's `fund_account` from the deployment's
  genesis-funded `E2E_PAYER` (`harness/lib/wallet.sh:104-144`). Size the budget
  from the **fee reserve** (~6.5e8 per transaction), not the registry price
  (~1e6); default `E2E_FUND_AMOUNT=5e9` covers several registrations
  (`wallet.sh:8-12`, `docs/contract.md:52`).
- The wallet must be essentially at chain head. A `register_member` from a
  stale wallet is dropped silently: the July manual demo (since deleted)
  observed "even a ~3-block lag drops the tx" and ran a 10 s re-sync loop
  beside the daemon. The lez module ≥ 3.0.0 owns its wallet and keeps it
  synced itself; the e2e harness syncs once before serving.
- Bounds: `get_registry_bounds(config)` returns `price_per_unit` and the
  rate range (100..600 today). The server clamps to `maxRateLimit`, and the
  registry rejects out-of-range rates at submission.

Environment the registry module reads (`liblogos_lez_rln_module.lidl:15-19`,
`README.md:100-107`): `LEZ_RLN_SEQUENCER`, `LEZ_RLN_NETWORK`, `LEZ_RLN_PAYER`,
`LEZ_RLN_PAYER_KEY`, `LEE_WALLET_HOME_DIR` (and `NSSA_WALLET_HOME_DIR`, which
the harness sets to the same dir). `LEZ_RLN_TREE_ID_HEX` is set by the harness
but not read by the lez module ≥ 4.x (the tree comes from the registry's
ConfigState). The hosted testnet (zone z3, LEZ v0.3.1, config
`fd322d32…b971`) is usable from a module built against lez 5.1.0; its payer is
funded by transfer, there is no faucet (the container route is in
`tools/allocator/docker/`; env flip: `tools/allocator/docker/README.md` §10).

---

## 4. Plugging in a validator (auth vector)

### 4.1 The contract already exists

A validator is any logos module exposing `verify_auth(json) -> json`; the
client half is `produce_auth`. The contract, the composition rule
(`auth_type` = `<scheme>-<authoriser>`), the binding digest, the payload
frame and the reasons are normative in `docs/auth-vectors.md`; the Rust form
is `crates/rln-auth-vector`. A vector may ship one or both halves (the
keycard scheme's producer is its own module so a headless gifter never
links PC/SC). A new scheme or authoriser implements one trait and composes
with every existing piece it accepts; a module in any language only has to
speak the JSON and the bytes.

### 4.2 Wiring it into the gifter

```json
"authVerifiers": {
  "my-app-voucher": { "module": "my_app_auth_module", "config": { "issuer_pubkey": "..." } }
}
```

- The key is the `authentication_type` string clients send. The vocabulary is
  open; pick your own.
- `config` is passed through verbatim on every call, so verifiers stay
  stateless (`server.rs:236-243`).
- An unknown type is refused with `unsupported authentication_type`
  (`server.rs:228-234`). With no `authVerifiers` at all, verification is
  skipped entirely (`server.rs:223`).
- The rate is settled **before** verification, so the verifier judges the
  number that will be registered (`server.rs:215-221`).
- A returned `nullifier` is lowercased, namespaced
  `"<registry>:<type>:<nul>"`, checked against the consumed set and reserved
  before the chain call; released only if nothing was submitted; appended to
  `consumedNullifiersPath` on success or on an unconfirmed submit
  (`server.rs`, `auth.rs`). A nullifier file written before 2026-11-05 holds
  `<type>:<nul>` lines: prefix each with the registry it was spent on (the
  config account as lowercase hex) or the credentials are spendable again.
- The verifier also gets `peer_id`, the requester as the libp2p stream
  proved it (`libp2p_module` ≥ 1.1.0 reports it from `protocolAcceptStream`);
  the `peer` scheme judges that and nothing else.

An "app-specific validator" is therefore: the app ships a verifier module
(loaded in the allocator daemon, named here) and usually a producer module
(loaded in its clients, named as `auth_provider`, §5.1). No change to
`rln_gifter_module` or `liblogos_rln_module` is required.

### 4.3 Reference vectors

Every composition below is verified by `rln_auth_module` and produced by
`rln_sign_module`, except the keycard scheme's producer
(`keycard_capture_module`, PC/SC). `rate_max` (default 100) and `audience`
(default `""`) come from `auth_args` and are bound into every digest but
eth's; the verifier refuses a rate above the signed `rate_max` and an
audience other than its `config.audience`. Operator files and tester
recipes per scheme: `docs/auth-allowlists.md`.

| `auth_type` | What proves what | Verifier `config` | Nullifier | Sybil-resistant? |
|---|---|---|---|---|
| `eth-allowlist` | a module-owned key (or any wallet, `personal_sign` over the lowercase hex commitment, framed) recovers to an allowlisted address; binds neither rate nor allocator (`auth-vectors.md` §4) | `{"allowlist": [addr…]}` | the address | only as far as the allowlist is |
| `logos-allowlist` | the tester's own logos-blockchain node zkSigns with an allowlisted key K | `{"allowlist": [K…], "audience": ""}` (`config/allowlist-logos.txt`, `LOGOS_ALLOWLIST`, `LOGOS_AUDIENCE`) | K (hex) | only as far as the allowlist is |
| `lez-allowlist` | a module-owned secp256k1 key (BIP-340) whose LEE account id is allowlisted | `{"allowlist": [id…], "audience": ""}` (`config/allowlist-lez.txt`, `LEZ_ALLOWLIST`, `LEZ_AUDIENCE`) | the account id (hex) | only as far as the allowlist is |
| `keycard-allowlist` | a card whose identity key is allowlisted | `{"allowlist": [ident_pub…]}` | the identity key | only as far as the allowlist is |
| `keycard-attestation` | a card whose identity key a trusted CA certified | `{"trusted_cas": [pubkey…]}` (`KEYCARD_TRUSTED_CAS`, default = Status production CA) | `keccak256(ident_pub)`, one per card | yes (hardware) |
| `logos-pow-claim` | the node's zkSign key owns a settled PoW reward claim on chain | `{"node_url", "audience"?, "min_payout"?, …}` (`docs/auth-pow-claim.md` §5; `POW_NODE_URL`) | the claim's `pow_nullifier` | yes (work), incomplete (§6 of that doc) |
| `peer-any` | the request arrived on a libp2p stream the requester's node key authenticated; any peer, one membership per peer id per registry (`auth-vectors.md` §3.3) | `{}` (`"audience"?`) | the peer id (multihash hex) | no: a peer id costs a key generation |
| `peer-allowlist` | the same, for a listed peer id | `{"allowlist": ["12D3Koo…"…]}` | the peer id | only as far as the allowlist is |
| `chat-installation` (design only) | — | — | — | no, identity only (`docs/auth-chat-installation.md` §7) |

**Commitment-bound payloads need a producer module.** Both reference payloads
are signatures over the identity commitment, and `liblogos_rln_module` mints
that commitment *inside* `register_membership` (§5.3), after the caller has
already supplied its options. A pre-made `auth_payload` therefore cannot be
bound to the right commitment through the membership module; only
`auth_provider` (a module the gifter client calls with the freshly minted
commitment) works there. Both reference vectors now have one: keycard's
`keycard_capture_module` (a physical card) and the allowlists'
`rln_sign_module` (`rust/rln-sign-module`; for eth the client daemon's own
secp256k1 key, generated on first use into
`<instance_persistence_path>/eth_sign_key.hex`, plaintext, 0600 — demo-grade
custody; the host must stamp a persistence path or the key is per-run). A
tester keeps an allowlisted address by `import_key`
(`{"scheme":"eth","private_key":"0x…"}`; add `"force": true` to replace a
different key already persisted). An app-specific vector
whose payload binds to the commitment must ship a producer half too. Proven
chainless by `tools/allocator/verify-chainless.sh` A9: the client's
`rln_sign_module.identity` id for eth-allowlist allowlisted on the
allocator, a `request` with `authProvider:"rln_sign_module"` reaches
`register_member`, and a foreign key is still refused.

A raw `auth_payload` works only when the caller also supplies the commitment
it is bound to, which is what the probe client (`CLIENT_IDENTITY_COMMITMENT`)
and `verify-local.sh` D8 do.

**The logos and lez allowlists** (`logos-allowlist`, `lez-allowlist`) follow
eth's pattern: the tester reports an identifier (`rln_sign_module.identity`
for the type: K, or the lez `id_base58`), you append it to
`config/allowlist-logos.txt` / `config/allowlist-lez.txt`, and the entrypoint
re-serves within 30 s (all three allowlist files are watched). Both are served
by default even while empty (a WARNING is logged and requests are answered
`allowlist is empty`); `LOGOS_ALLOWLIST=0` / `LEZ_ALLOWLIST=0` switch them off.
One verifier, `rln_auth_module` (bundle `rln-auth-module.lgx`),
serves all three allowlist types and must be in the image. Payload
layouts, digest domains and refusal strings: `docs/auth-allowlists.md`. Proven
by `verify-chainless.sh` A11/A12 and `verify-local.sh` D9/D10.

### 4.4 Operator traps

- **The allocator's `libp2p_module` answers only the serve worker.** The
  worker's `protocolAcceptStream` is a condvar wait inside libp2p_module's
  call dispatcher, so while one is pending (2 s at a time, back to back) any
  other call to that libp2p_module — `peerInfo` from the CLI, a `discover`
  or `request` on the same node, a second module — times out. An allocator
  node is an allocator only; `serve` advertises before it spawns the worker
  and hands later advertisement changes to the worker.

- **A verifier module that is not loaded is not caught by `serve`.** The host
  defers the client creation, so the first real request fails
  (`tools/pow-claim-poc/README.md`, corrections 16 and R2.4).
- **A missing `liblogos_lez_rln_module`** is likewise not detected at `serve`;
  the first `register_member` waits ~190 s and the request fails.
- **`logoscore call` has a ~20 s CLI deadline.** A `serve` or `request` that
  outlives it keeps running in the daemon but the CLI reports nothing
  (`tools/pow-claim-poc/README.md` R2.4). Drive long operations from a module
  or read results back through state, not the CLI reply.
- **The client never sees `auth_success=false` as such.** The gifter client
  collapses "auth refused" and "auth accepted, registration failed" into one
  `{"error": …}` string (`client.rs:120-132`); the RLN module records it as
  `failed_reason: "gifter_failed: …"` (`logos-rln-module/rust-lib/src/lib.rs:541-550`).
- **The rate clamp is silent.** A client asking for 600 against
  `maxRateLimit: 100` gets 100 with no notice until its poller reads the
  chain.

---

## 5. Client side: a user's RLN module using the allocator

### 5.1 It is a per-call choice, not a mode

There is no node-level "use allocator X" setting. Delegation is selected on
each `liblogos_rln_module.register_membership(registry_id, rln_identifier_hex,
options_json)` call through RegistryOptions, a JSON array of string pairs
(`logos-rln-modules/logos-rln-module/rust-lib/liblogos_rln_module.lidl:141-184`,
parsing at `rust-lib/src/lib.rs:660-739`):

| key | value | notes |
|---|---|---|
| `delegated` | `"true"` (exact string) | selects the allocation protocol (`flat_bool_option`, `lib.rs:379`) |
| `discover` | `"true"` (default) / `"false"` | ask the allocators advertising the (registry, auth_type) pair first (§2.5); `"false"` dials the configured pair alone (0.15.0) |
| `gifter_peer_id` | PeerId | together with `gifter_multiaddr`, or neither; asked after the discovered ones. Required when `discover` is `"false"` |
| `gifter_multiaddr` | multiaddr without `/p2p/` | see `gifter_peer_id` |
| `auth_type` | vector name | optional; omitted = unauthenticated request for an open gifter |
| `auth_payload` **xor** `auth_provider` | hex payload, or a producer module name | exactly one, and only with `auth_type`; checked before a credential is minted |
| `auth_args` | opaque string | forwarded verbatim to the producer |
| `rate_limit` | decimal string | default 100 (`DEFAULT_RATE_LIMIT`, `lib.rs:397`); out-of-bounds fails before minting |

The RLN module turns these into the gifter client's
`{discover, config, identityCommitment, rate, gifterPeerId?,
gifterMultiaddr?, authType?, authPayload?, authProvider?, authArgs?}`
(`lib.rs`, `delegated_request_args`) and calls `rln_gifter_module.request`
through its generated client with a 340 s budget (`provider.rs`).

### 5.2 What a client node must have loaded

| Module | Role on the client |
|---|---|
| `liblogos_rln_module` | mints the identity, holds the keystore, owns the membership record and the confirmation poller |
| `rln_gifter_module` | client half (`request`) |
| `libp2p_module` | the client's own node; `createNode {"addrs":["/ip4/127.0.0.1/tcp/0"], "mountServiceDiscovery": true, "bootstrapNodes": [...]}` + `start` to discover allocators (§2.5); without discovery, the configured pair alone (`consumer-gifter/run.sh:165-167`; UI: `membership.js:74-87`) |
| `liblogos_lez_rln_module` | **read-only** chain access for the poller (`get_membership`, roots). Its wallet is never funded (`consumer-gifter/run.sh:10-12, 153-160`) |
| producer module (e.g. `keycard_capture_module`) | only if the vector needs one |

### 5.3 Flow and confirmation

1. `register_membership` validates the options, checks the rate against the
   registry bounds, **then** generates the identity inside the module and
   stores it encrypted; the record is `pending` before anything is sent
   (`lib.rs:767-810`). The identity secret never leaves the module; only the
   commitment reaches `rln_gifter_module`.
2. The gifter client obtains the auth payload (raw, or via the producer with a
   120 s budget), sends one `RlnGifterRequest` with
   `request_id = "gift-" + first 16 hex of the commitment`, reads one reply
   (`client.rs:95-115`).
3. On a reply the RLN module records the leaf estimate and a funded-style
   `tx_result`; on `{"error"}` a still-pending record becomes `failed`
   (`lib.rs:532-582`).
4. **Confirmation is the registry's, not the gifter's.** The poller re-reads
   every pending record from the registry every 15 s; observed ⇒ `active` with
   the authoritative `leaf_index` and `rate_limit` read from the chain; not
   observed within `CONFIRMATION_WINDOW_SECS = 300` ⇒ `failed`
   (`poller.rs:1-12`, `lifecycle.rs:74-76`). This is a spec MUST
   (`rln-membership-management.md:591-596`).
5. The caller polls `get_membership_state` for `pending → active`
   (`consumer-gifter/run.sh:199-216`; `chat-basecamp-gifter/run.sh:378-393`).

Funded versus gifted:

| | Funded (`delegated` absent) | Gifted |
|---|---|---|
| who signs and pays | the client's own `liblogos_lez_rln_module` payer (`provider.rs` `LezRlnProvider::register_async`) | the allocator's `wallet` |
| what the client needs | a funded, synced wallet | a libp2p node with discovery, or a `(peer id, multiaddr)`, and optional auth material; chain read access |
| identity, keystore, poller, confirmation | identical | identical |
| automatic provisioning at `start()` | yes (`ensure.rs`, funded only) | **no** |

### 5.4 Surfaces that drive it today

- **nim-rln-consumer** (delivery's RLN seam mock): `registerMembership
  "str:<rate>" '{"delegated":"true","gifter_peer_id":…,"gifter_multiaddr":…}'`,
  flattened into RegistryOptions (`logos-rln-e2e/nim-rln-consumer/nim-lib/src/rlnconsumer.nim:122-142`;
  `consumer-gifter/run.sh:188-193`).
- **Basecamp**: `liblogos_rln_module.register_membership` called directly with
  the options array (`chat-basecamp-gifter/run.sh:371-374`).
- **Membership UI** (`logos-rln-membership-ui`): at 0.7.4 it hardcoded
  `auth_type: "keycard-attestation"`, `auth_provider: keycard_capture_module`
  and a demo gifter's PeerId as defaults. 0.8.0 (branch
  `feat/membership-ui-0.8.0`, 2026-10-12) makes it the reference client
  configuration: an "allocator" step with the peer id, multiaddr, an
  auth-vector picker over `membership.js` `AUTH_VECTORS` (open, keycard,
  eth-allowlist → `rln_sign_module`, whose address the step shows for the
  operator to allowlist; that producer is now `rln_sign_module`, so the
  UI's eth vector must name it and read `identity` instead of `address`) and optional `auth_args`; one builder
  (`M.delegatedOptions`) emits the RegistryOptions for both the wizard
  (`OnboardingFlow.registerDelegated`) and the expert tab
  (`RegisterView.doRegister`). Its funded path moved from the removed
  lez_core wallet + faucet to `ensure_membership` + the `provisioning`
  object (rln 0.12.0, branch `feat/intents`), rendering "send `required` to
  `payer`". The flow controller carries `objectName: "flowController"` and
  the step's fields `gifterPeerIdField`, `gifterMultiaddrField`,
  `authTypeSelector`, `authArgsField`, `registerDelegatedButton` for a
  headless driver.

Not available: any delivery or chat configuration key. Upstream
`logos-delivery` dropped the LEZ conf keys and `configureRln` carries only
`registry-id`, `rln-identifier`, `epoch-size-sec`
(`chat-basecamp-gifter/run.sh:30-38, 357-369`; the mention of
`rln-relay-registry-options` in that scenario's `scenario.env:6` is stale).
So an application today reaches the allocator only by calling
`register_membership` itself.

---

## 6. Assembled recipe: a third-party allocator as it would run today

**Released-tooling route (2026-10-15):** `tools/allocator/docker/` packages
the same recipe for a host that runs `logosctl` in Docker — released
`logosctl` 0.3.0, the catalog's portable `libp2p_module` 1.1.0 and
`liblogos_lez_rln_module` 5.1.0, and this repo's modules as `lgx-portable`
bundles built on the host (`build-bundles.sh`); one container, one volume,
serve re-issued on every start, pow-claim + keycard-attestation + eth-allowlist served together,
the allowlist re-served on edit. Runbook: `tools/allocator/docker/README.md`;
tester side: `docs/testers-getting-a-membership.md`. Verified here on
2026-10-15 (`docker/verify-local.sh`, linux-arm64 image, payer unfunded):
portable bundles load under released `logosctl`, PeerId stable across
`compose restart` and a daemon kill with automatic re-serve, allowlist edit
re-serves, and an eth-allowlist request from a host client reaches
`register_member` and is refused `insufficient_balance` with nothing paid.
Trap: `libp2p_module.peerInfo` hangs or fails intermittently once the gifter
has mounted its protocol (4 of 6 calls from a second client) — read the
PeerId before `serve`, probe liveness on the socket.
**First real grants through the container (2026-10-15/16):** this Mac hosts
the container (PeerId `16Uiu2HAkwLPo…`, `/ip4/192.168.1.36/tcp/9000`); the
user's Intel Mac runs the client container (`docker/client-compose.yml`,
linux-amd64 bundles it built itself) and connected over the LAN at first
try. Against a local LEZ v0.3.1 zone kept up by the e2e agent (sequencer
`*:3040`, reached from the container as `host.docker.internal:3040`; metrics
moved to 9100 because the allocator holds 9000; registry
`logos:local:7bd1e28e…d4db`; the allocator's derived payer
`8f5388c8…fa86` funded 5e9 by `fund_account` from the genesis payer): an
eth-allowlist request from a pinned key was granted **leaf 1** in 3 s
(`auth_success:true`, tx hash returned), the payer paid 74,127,304, the
nullifier `eth-allowlist:0x17c5…` was persisted, and a replay with the same
key was refused `credential already used`. Operational trap found on the
way: a bind-mounted FILE keeps the inode it was mounted with, so editor
saves and `sed -i` never reach the container — the allowlist is read from a
bind-mounted DIRECTORY (`docker/config/`).
**pow-claim verifier node (2026-10-16):** the allocator's `POW_NODE_URL`
now resolves to a FOLLOWER logos-blockchain node in Docker
(`tools/allocator/docker/node/`, image 0.3.2, config generated by the
module's own `generate_user_config`, bootstrap period patched 3600 s → 5 s,
peers = the public testnet bootstrap nodes, API on the host loopback only).
It left initial block download after 3.5 min (14k blocks) and reports
`Following/Online`, `lib_slot` ≈ 41k slots behind the tip: on this chain
(public testnet 0.3.2, 1 s slots, measured ~41 s per block, finality =
1000 blocks, about **11 hours**; producer scan window 3000 slots, about **50
minutes** after finality) a claim is usable about 11 hours after it is
mined, and pinning is the normal path: the claim must be pinned (`claim_block_id` +
`pow_nullifier`). Inside the allocator container
`rln_auth_module.verify_auth` with a genuine credential from the PoC's
standalone chain was refused `claim block unknown to node:` (the verifier
reached the follower and found the block foreign), and with a dead
`node_url` answered `node unreachable or failing: …Connection refused`.
Mining-side facts for the tester's node (0.3.2 routes): `PUT
/pow/mining/start` (never on by default, off again after a restart),
`GET /pow/rewards/claimable`, `GET /pow/status`; a config made by
`init-config` arms auto-claim with its own `PoWClaim` key (tick 10 s).
**Real tickets, 2026-10-16:** the Intel Mac's node (0.3.2, mining) won two
tickets at 02:33 and 02:39 UTC, auto-claim landed them in the blocks at
slots 561875 and 562201, they became final ~13:50 UTC (LIB 1000 blocks
behind), and at 15:49 UTC the Intel Mac client registered **both** through
the container: the verifier accepted nullifiers `11011cac…` and `83f4f584…`
(audit `path:"spent_to"`, 29–60 ms per verify against the follower), the
payer paid 74,142,108 twice, the local registry went to 5 registrations,
and both `logos-pow-claim:<nullifier>` lines are in the consumed-nullifier file.
Traps hit on the day: the host's DHCP address changed after a network
drop, so the pinned `/ip4/…/tcp/9000` stopped routing (the PeerId did not
change; the client only had to dial the new address — advertise a stable
address); and by the time the client ran, the claims
were already outside the producer's default 3000-slot scan window, so the
request had to pin the claim (`claim_block_id` + `pow_nullifier`,
`tools/allocator/docker/node/find-claims.py` lists them) or widen
`scan_window_slots`/`scan_depth_blocks`.
**Three vectors, public exposure, switch drill (2026-10-16):** the container
now also serves `keycard-attestation` (`rln_auth_module`, env
`KEYCARD_TRUSTED_CAS`, default = the Status production CA); synthetic cards
minted with `tools/mint_attest.py` under a host-local test CA were refused
(untrusted CA), granted (leaf on the local zone) and replay-refused through
the client container (`verify-local.sh` D8), then the test CA was removed.
Public exposure was verified with a real gifter reply to a client container
on a machine on another network. `allocator.json` now carries
`alt_multiaddrs` beside `gifter_multiaddr`. The local ↔
testnet switch was drilled live: 32 s to serve on testnet with the existing
unfunded payer (probe: `insufficient_balance … needs 91900000`), 2 s back,
same PeerId. Both remaining checks then passed: a real Status Keycard (ACS ACR39U
reader, `tools/allocator/docker/keycard-native.sh`) was granted leaf 9 in 9 s
and replay-refused, and the Intel Mac, from another network, reached the
allocator. The testnet payer was then funded
(500,000,000) and the first hosted-testnet grant went through from this
host's client container: the logosctl call deadline (~20 s) hid the reply,
the registration landed by 90 s (payer paid 74,161,352), a re-send was
refused `credential already used`; the probe client now re-sends after a
wait and reports that as the grant. `register_membership` (asynchronous) is
unaffected. The Intel Mac then registered twice more on testnet from the
public internet (eth-allowlist and a pinned
pow-claim, ~74.2M each, nullifiers persisted, verifier 21–28 ms): the
three-vector allocator, public exposure and the hosted registry are all
exercised end to end; what remains is a real tester through
`register_membership` with a usable identity.
**Two registries on LEZ v0.4.0-rc1 (2026-11-05, e2e `rln-allocator` on
feat/two-registries, run 20261105-161119):** PASS — one allocator (persisted
key) serving the delivery registry D and the mix registry M with
`peer-any` and `eth-allowlist` on `rln_auth_module`, two never-funded
clients registering through `liblogos_rln_module.register_membership`:
c1 `peer-any` on D (leaf 7), the same peer on D refused `credential already
used: <D>:peer-any:<peer>`, the same peer on M (leaf 5), c2 on D (leaf 8),
c1 `eth-allowlist` through `rln_sign_module` (leaf 9) and c2's address
refused by name, an unserved registry refused `registry not served` and an
invalid commitment refused client-side, the allocator restarted on the same
PeerId with c1 still refused and c2 landing on M (leaf 6); 369,568,048 paid
for five memberships (price 1e6 each, the rest fees). Client-side trap: once
a registry holds two of a node's memberships, `get_membership_state` by
scope answers `ambiguous_selection`; the scenario polls the record by
`membership_hash` through `get_memberships` instead.
**Status:** steps 1–6 are implemented as `tools/allocator/run-allocator.sh`
(`up` / `serve` / `status` / `down`, persisted node key, `allocator.json`
hand-off; see `tools/allocator/README.md`). `tools/allocator/verify-chainless.sh`
runs it against the PoC stub registry module and the real `eth_auth_module`
verifier and asserts: serve with a verifier, refusal of unauthenticated and
malformed requests, verifier reject by address, verifier accept reaching
`register_member` exactly once with nullifier release, **identical PeerId
after a daemon restart**, a client served after that restart, and a `serve`
refresh to open. Verified 2026-10-09 (`tools/allocator/runs/<ts>/summary.json`).
**On-chain leg:** covered by the e2e agent on `--target local` (LEZ v0.3.0
pins, gifter 0.3.0, `eth_auth_module`, upstream `libp2p_module` 1.0.0),
2026-10-09, in `logos-rln-e2e/scenarios/rln-allocator/{scenario.env,run.sh}`
on branch `feat/rln-allocator` (stacked on `chore/relock-lez-v0.3.0`, pushed
not merged; `feat/rln-allocator` local at the time of writing). Observed:
non-allowlisted key refused with the gifter balance unchanged; client A
registered at leaf 0 matching the gifter's answer; gifter restart on the
persisted key kept the PeerId, re-served, and client B on the old `(peer id,
multiaddr)` registered at leaf 1; A's key after the restart refused as
`credential already used: eth-allowlist:0x17c5…` with nothing paid; the payer
paid 148,277,984 native for the two memberships. The membership-module leg
(`register_membership` → `pending → active`) through an open gifter is the
sibling scenario `delivery-rln-gifter` (branch `feat/delivery-rln-gifter`,
same stack). The eth path there goes through `rln_gifter_module.request`
directly, for the reason in §4.3.
**Re-run on LEZ v0.3.1 (2026-10-14, e2e agent, e2e branch `test/gifter-v031`
= `chore/lez-v0.3.1` + both scenarios; rln-modules `main` bundles lez 5.1.0 /
rln 0.12.0; gifter built from `feat/eth-sign-module` with the BN254
pre-check):** `rln-allocator` PASS — the non-canonical commitment is now
refused client-side as `{"error":"invalid_commitment: not a BN254 field
element (little-endian value >= r)"}` with nothing paid, A at leaf 0, same
PeerId after restart, B at leaf 1, A's reused credential refused, the payer
paid 148,267,320 for two, and the mismatched registry went pending → failed
(`confirmation_window_elapsed`) after 305 s. `delivery-rln-gifter` PASS — a
never-funded node got leaf 0 from the gifter (74,158,592 paid) and its peer
received the proof-gated message (delivery module from logos-delivery PR
#160). Local registry for both:
`logos:local:7bd1e28e47b1e50f96d806ed96e4214c762ab2b639a9bed2b45dede16099d4db`,
genesis-funded deployment payer. The harness mints canonical commitments as
`$(openssl rand -hex 31)00`. Later the same day, with a Basecamp build:
`chat-basecamp-gifter` gifter half PASS (fundless Basecamp registered
delegated at leaf 0, gifter paid 74,128,728, Basecamp paid 0) while its chat
leg failed on the chat-module fork `rln/e2e-extra-conf` not parsing delivery
0.4.0's `messageReceived` event — not gifter-side. **`membership-ui-gifter`
PASS** (`runs/20261014-171511-membership-ui-gifter-local`): the UI 0.8.0
mounted in headless Basecamp with no missing-deps popup; Tier 1 replayed the
UI's exact eth options (delegated, peer id + multiaddr, `auth_type`
eth-allowlist, `auth_provider` rln_sign_module) → active at leaf 0, allocator
paid 76,134,640 (price 3e6), Basecamp paid 0; re-served on another allowlist
the same request failed as `gifter_failed: address not allowlisted: 0x2ea8…`,
the persisted module key's address. **Tier 2 is reachable:** the inspector's
`findByProperty objectName=flowController` returns the OnboardingFlow item
inside Basecamp's sandboxed QQuickWidget engine (the earlier doubt in §5.4 is
resolved); driving `startGifter` through it is not done yet. Three findings
for this side: the tracked `keycard_capture_module` `result-lgx` was built by
an older builder for variant `darwin-arm64`, which current Basecamp rejects
("not supported on this platform"; the current builder emits
`darwin-arm64-dev`) — rebuilt; the gifter clamps to `DEFAULT_MAX_RATE` 100
silently while the UI asked 300 — the UI's allocator path now asks for the
registry minimum (`delegatedRateLimit`), and the scenario re-run at rate 100
against an allocator served with NO `maxRateLimit` (the gifter default)
passed again (`runs/20261014-173138-membership-ui-gifter-local`, rebuilt UI
and keycard bundles, allocator paid 74,163,360, Basecamp 0); and once a
delegated membership
exists, `get_membership_state(registry, <another rln_identifier>)` answers
`ambiguous_selection` (§7, Goal C). The hosted-testnet run (z3,
env flip: `tools/allocator/docker/README.md` §10) waits on payer funds.

Operator side:

1. **Build and install** `.lgx` bundles: `rln_gifter_module`
   (`nix build ./rust/rln-gifter-module#lgx`), your verifier module,
   `libp2p_module` (`nix build <logos-libp2p-module>#lgx`),
   `liblogos_lez_rln_module`; `lgpm --modules-dir <dir> --allow-unsigned
   install --file <lgx>` for each. (The e2e flake does not pin the gifter or
   libp2p yet; both resolve from `GIFTER_CHECKOUT` / `LIBP2P_MODULE_CHECKOUT`,
   `harness/artifacts.sh:205-228`.)
2. **Mint the node key once** and store it outside any wipeable work dir:
   `logoscore call libp2p_module newPrivateKey` → `gifter_node_key.hex`.
3. **Start the daemon** with the registry module's environment:
   `LEZ_RLN_SEQUENCER` (or `LEZ_RLN_NETWORK`), `LEZ_RLN_TREE_ID_HEX`, and
   either `LEZ_RLN_PAYER` + `LEZ_RLN_PAYER_KEY` or a wallet home via
   `LEE_WALLET_HOME_DIR`; then `logoscore -D -m <modules>`; `load-module` in
   the order of §1.1.
4. **Wait for the wallet**: poll `liblogos_lez_rln_module wallet_status` until
   `state == "ready"`; note `payer`. Fund that account with native balance
   sized from the fee reserve (§3.3). Keep it synced for the daemon's lifetime.
5. **Bring up libp2p**: `createNode {"privKey": <hex>, "addrs":
   ["/ip4/<routable-ip>/tcp/<port>"], "mountGossipsub": false, "mountKad":
   false, "mountServiceDiscovery": false, "maxConnsPerPeer": 1, …}`; `start`;
   `peerInfo` → **publish `peerId` and the dial multiaddr to your users**.
6. **Serve**: `rln_gifter_module serve {"config": "<registry config
   account>", "wallet": "<payer>", "authVerifiers": {"<type>": {"module":
   "<verifier>", "config": {…}}}, "consumedNullifiersPath": "<persistent
   file>", "maxRateLimit": 100}`. Repeat after every restart.

User side (inside the app, after loading §5.2's modules and starting its own
libp2p node):

7. `liblogos_rln_module register_membership "logos:<ref>:<config-hex>"
   "<rln_identifier_hex>" '[{"key":"rate_limit","value":"100"},
   {"key":"delegated","value":"true"}, {"key":"gifter_peer_id","value":"<peerId>"},
   {"key":"gifter_multiaddr","value":"<multiaddr>"},
   {"key":"auth_type","value":"<type>"}, {"key":"auth_provider","value":"<producer module>"}]'`
8. Poll `get_membership_state` until `active`.

---

## 7. Gaps, mapped to the three goals

Each bullet is a candidate follow-up task. "Exists" means working in the code
at the revisions above.

### Goal A: a standalone allocator module per application

Exists: the module, the single `serve` call, serialized registration, chain
read-back confirmation, replay protection, a worked open-gifter bring-up in two
e2e scenarios.

Missing:

- No binary, config file or CLI in the module itself; `serve` is in-memory
  and must be re-issued after every restart. `tools/allocator/run-allocator.sh`
  wraps this from the outside (env or an `allocator.env` file, `up` re-serves), but
  nothing inside the daemon re-serves from persisted config.
- The identity key is not persisted unless the operator does it.
  `tools/allocator/run-allocator.sh` persists it (`node_key.hex`) and `tools/allocator/verify-chainless.sh`
  proves the PeerId survives a restart, on loopback. No e2e scenario does
  either, and nothing yet exercises a routable (non-loopback) listen/advertise
  address.
- `libp2p_module.createNode` accepts a bad config with `success:true` and
  silently runs on a fresh key and random port (§2.4); nothing in the gifter
  stack notices until clients fail to dial. Needs either a hard failure in
  `libp2p_module` or a post-start identity/address assertion in every
  bring-up path.
- One wallet per gifter: every served registry is paid from `serve`'s
  `wallet`.
- Funding is manual (no faucet). The hosted testnet run exists in
  `tools/allocator/docker/` (§6, 2026-10-16 records) and waits on payer
  funds; wallet staleness silently drops registrations and
  nothing in the module keeps the wallet at head.
- No throughput or abuse controls: one worker, no per-peer limit, no queue
  cap; an open gifter is a drain on its payer.
- **Invalid-field-element drain (found by the e2e agent 2026-10-09, closed
  on the lez side in 5.1.0):** on lez module ≤ 5.0.0 a 32-byte commitment
  that is not a BN254 scalar (little-endian) passed the gifter and
  `register_member`; the guest panicked, the fee was charged, and the watcher
  re-sent five times: ~4.8e8 per bad request versus ~7.4e7 for a real one
  (§1.3). `register_member` 5.1.0 (`feat/check-registry`, `5ac03c4`) refuses
  it before signing, and since 2026-10-14 the gifter refuses it at both
  ends as well (`wire::commitment_refusal`, used by `handle_request` and
  `request`; `verify-chainless.sh` A10). Closed.
- The gifter and libp2p bundles are not pinned in the e2e flake.

### Goal B: a pluggable per-app validator

Exists: the `rln_auth_vector` contract, config-only wiring, three reference
verifiers (one a PoC), namespaced nullifiers with persistence.

Missing:

- `serve` does not check that the named verifier modules are loaded.
- A commitment-bound vector without a producer module cannot be used through
  `liblogos_rln_module` at all, because the commitment is minted after the
  options are fixed (§4.3). Closed for eth-allowlist by `rln_sign_module`
  (2026-10-12), now `rln_sign_module` for all three allowlist types; what remains is the general point — an external wallet
  cannot sign through the membership module without a two-step register
  that returns the commitment before the gifter request — and the demo-grade
  key custody of the new producer (plaintext key file).
- `auth_success` is not surfaced to the client as a distinct outcome.
- No app identifier on the wire (the registry is there since 2026-11-05),
  so a verifier cannot scope its decision per app.
- The rate clamp is not reported in the reply.
- The advertisement names the served (registry, vector) pairs as digests
  (§2.5), not the vectors by name: a client must know which vector it wants.
- pow-claim is incomplete (`docs/auth-pow-claim.md` §6C, §7).

### Goal C: users configuring their RLN module to use the allocator

Exists: the per-call RegistryOptions path through `liblogos_rln_module`, with
the identity never leaving the module and registry-based confirmation; the
membership UI 0.8.0 as the reference client configuration (allocator step,
auth-vector picker, `M.delegatedOptions`), proven on local LEZ v0.3.1.

- Scope resolution after several memberships: `get_membership_state` on a
  scope with more than one candidate answers `ambiguous_selection` (observed
  by the e2e agent once a delegated membership coexisted with another
  scope's). A client polling by scope must then fall back to
  `get_memberships` and match its row by `membership_hash` / commitment; the
  UI does not yet (its own registrations share one scope and short-circuit,
  so it has not hit it).
- The rate clamp is silent: the gifter caps at `maxRateLimit` (default 100)
  and the membership module flags `rate_limit_mismatch` against the ask. The
  UI's allocator path asks for the registry minimum for that reason; an
  allocator raising its cap has no way to advertise it.

Missing:

- No persistent "allocator" setting on the RLN module, and `start()`
  auto-provisioning is funded-only, so applications must call
  `register_membership` themselves.
- No delivery or chat configuration key reaches the allocation protocol.
- (closed 2026-11-05) The client cross-checks the gifter's
  `config_account_id` against its own registry, and the gifter refuses a
  registry it does not serve (§3.1).
- (closed 2026-11-06) Allocators are discovered through libp2p service
  discovery and tried in turn; the configured pair is the fallback (§2.5).
  Still one configured pair per call.
- The deterministic `request_id` is never actually reused: a retry mints a
  fresh identity (`lib.rs:787`), so LIP-158's dedup intent is not exercised.
- Stacked timeouts set by hand: RLN module 340 s > gifter client 190 s >
  server confirm 150 s, with the 300 s pending window independent of all
  three.

### Artifacts not to trust

- `logos-rln-e2e/scenarios/mix/*`: old gifter API compiled into
  `libp2p_module`, dead pins, personal forks; see `scenarios/mix/STATUS.md`.
- `chat-basecamp-gifter/scenario.env:6`: refers to a conf key that no longer
  exists.

---

## 8. Sources

Specs:
- [LIP-158] RLN Membership Allocation: `logos-lips/docs/anoncomms/raw/rln-membership-service.md`
- Delegated registration in the membership-management spec: `logos-lips/docs/anoncomms/raw/rln-membership-management.md:575-600`

This repo:
- `README.md` (module overview, flow, auth, registration, build)
- `crates/rln-auth-vector/README.md` (how to write a vector)
- `docs/auth-pow-claim.md`, `docs/auth-chat-installation.md` (vector designs)
- `tools/pow-claim-poc/README.md` (two-daemon harness, host pitfalls)
- `rust/rln-gifter-module/rust-lib/src/{server,client,wire,auth,lp}.rs`

Modules:
- `logos-rln-modules/logos-rln-module/rust-lib/liblogos_rln_module.lidl:141-184` and `docs/wire-binding.md:283-318` (RegistryOptions)
- `logos-rln-modules/logos-rln-module/rust-lib/src/{lib,provider,poller,lifecycle,ensure}.rs`
- `logos-rln-modules/logos-lez-rln-module/rust-lib/liblogos_lez_rln_module.lidl`, `README.md` (payer, env)
- `logos-libp2p-module-master/README.md`, `config.example.json`, `src/plugin.cpp`, `src/protocol_bridge.cpp`

E2E:
- `logos-rln-e2e/docs/contract.md`, `deployments/README.md`
- `logos-rln-e2e/scenarios/consumer-gifter/run.sh`, `scenarios/chat-basecamp-gifter/run.sh`
- `logos-rln-e2e/scenarios/rln-allocator/` (branch `feat/rln-allocator`) and
  `scenarios/delivery-rln-gifter/` (branch `feat/delivery-rln-gifter`), both
  stacked on `chore/relock-lez-v0.3.0`; not on `master` at the time of writing
- `logos-rln-e2e/harness/lib/{daemon,wallet}.sh`, `harness/container/entrypoint.sh`, `harness/artifacts.sh`


[LIP-158]: https://lip.logos.co/anoncomms/raw/rln-membership-service.html
