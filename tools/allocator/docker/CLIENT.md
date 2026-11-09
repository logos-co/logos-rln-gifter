# Client machine: load the modules and talk to the hosted allocator

For the machine that will register memberships through the allocator (an
Intel Mac running Docker, for the first test). Goal of this step: the client
modules load, a libp2p node comes up, and one request reaches the allocator
and is answered. No funds, registry or RLN module are involved yet.

## 0. What you get from the allocator operator

From their `allocator.json`:

- `gifter_peer_id` — e.g. `16Uiu2HAkwLPoBeGUuxmepC7acikGSmQddfWWyajd2KspnDLV1J8o`
- `gifter_multiaddr` — e.g. `/ip4/<allocator host ip>/tcp/9000` — the two
  machines must be able to reach that address and port (same LAN, a VPN, or
  a forwarded port). LAN alternatives are in `alt_multiaddrs`. Use an IPv4 address, never a name: a
  `/dns4/host.docker.internal/…` multiaddr does not resolve inside the client
  container (nim-libp2p's resolver does not read `/etc/hosts`).
- `registry_id` — the registry the allocator pays on.

An allocator that advertises through the DHT needs none of the first two:
the client finds it from `registry_id` (discovery mode, §3).

The operator fetches `allocator.json` with
`docker compose exec allocator cat /var/lib/allocator/allocator.json` and
hands it to you. It maps onto `client.env` as:

| `allocator.json` | `client.env` |
|---|---|
| `gifter_peer_id` | `ALLOCATOR_PEER_ID` |
| `gifter_multiaddr` (or one of `alt_multiaddrs`) | `ALLOCATOR_MULTIADDR` |

The client container does not choose the registry: the allocator's
`registry_id` does. Check `registry_id` in the `allocator.json` you were given
before testing (the operator can switch it, README §10; a tester pinned to
the other registry sits `pending`).

## 1. Get the code

```sh
git clone -b feat/allocator git@github.com:logos-co/logos-rln-gifter.git
cd logos-rln-gifter/tools/allocator/docker
```

## 2. Build the portable bundles (~10–15 min the first time)

Needs Docker Desktop (compose v2). The build runs inside a `nixos/nix`
container native to the machine's architecture and produces the bundles the
image installs (`rln_gifter_module`, `rln_auth_module`, `rln_sign_module`).

```sh
./build-bundles.sh
ls bundles/     # rln-gifter-module.lgx rln-auth-module.lgx rln-sign-module.lgx
                # rln-sign-module.lgx rln-auth-module.lgx
                # rln-auth-module.lgx
```

Each bundle must report the variant `linux-amd64` (Intel) — no `-dev`.

## 3. Configure the client

```sh
cp client.env.example client.env
$EDITOR client.env      # ALLOCATOR_PEER_ID and ALLOCATOR_MULTIADDR from step 0
```

Two modes, chosen by `client.env`:

- Pinned: `ALLOCATOR_PEER_ID` + `ALLOCATOR_MULTIADDR` name the allocator.
- Discovery: `ALLOCATOR_PEER_ID` empty, `REGISTRY_CONFIG` set to the
  registry's ConfigState account (hex or base58), and `KAD_BOOTSTRAP_NODES`
  (comma-separated `<multiaddr>/p2p/<peerId>` DHT peers; `client.env.example`
  lists the logos.test fleet entry nodes). The client's libp2p node is created
  with `mountKad:true`, `mountServiceDiscovery:true` and those peers, waits up
  to 20 s for a connected peer, and looks up an allocator advertising
  `REGISTRY_CONFIG` for `CLIENT_AUTH_TYPE`. A miss reads
  `discovery not joined: no connected peer after 20s` or
  `no allocator advertises <registry>/<type>`, returned as the request's error.
  `CLIENT_MODE=delivery` needs the pinned mode.

## 4. Run the probe

```sh
docker compose -f client-compose.yml run --rm client
```

What it does, and what to expect in the output:

1. starts a `logosctl` daemon, loads `libp2p_module`, `rln_gifter_module`
   and `rln_sign_module` (the official catalog provides the first, the
   other two come from your bundles), and prints the loaded modules;
2. brings up a libp2p node on an ephemeral port and prints its PeerId;
3. prints this machine's eth-allowlist address (`rln_sign_module`
   `identity`, or `import_key` when `CLIENT_AUTH_ARGS` carries a
   `private_key`; for logos-/lez-allowlist the node key K / the base58 account
   id) — send it to the operator if you want to go further than connectivity. Set
   `CLIENT_AUTH_ARGS={"private_key":"0x…"}` in `client.env` first: a
   `run --rm` client gets a fresh module key (and address) every run
   otherwise, and the operator's allowlist entry would go stale;
4. sends one allocation request to the allocator and prints the reply.

Knobs in `client.env` (the tester procedure for each vector is
`docs/testers-getting-a-membership.md` recipes A/B/C):

| Knob | What |
|---|---|
| `CLIENT_AUTH_TYPE` | vector: `eth-allowlist` (default), `logos-allowlist`, `lez-allowlist`, `logos-pow-claim`, `keycard-attestation`, or `none` |
| `CLIENT_AUTH_PROVIDER` | producer module: `rln_sign_module` (default; every scheme but the PC/SC keycard, picked by `CLIENT_AUTH_TYPE`); ignored with `CLIENT_AUTH_PAYLOAD` |
| `CLIENT_AUTH_ARGS` | producer args (a JSON object, or that object as a JSON string). eth: `{"private_key":"0x…"}`. lez: `{"private_key"?:"0x…","rate_max"?:100,"audience"?:""}`. logos: `{"node_url":"http://host.docker.internal:18080","public_key"?:"<64 hex>","rate_max"?:100,"audience"?:""}` (your own node; the key it reports is printed for the operator). logos/lez: `rate_max` (default 100) is signed and must be ≥ `CLIENT_RATE`; `audience` (default `""`) must equal the operator's `LOGOS_AUDIENCE` / `LEZ_AUDIENCE`. A `private_key` is imported (`import_key`; add `"force":true` to replace a different persisted key) and then removed from the args sent with the request. pow-claim: `{"node_url":"http://host.docker.internal:18080","audience":"","rate_max":100,"claim_block_id":"<hex>","pow_nullifier":"<hex>"}` (testers doc recipe B step 4; `audience` must equal the operator's `POW_AUDIENCE`, currently empty) |
| `CLIENT_AUTH_PAYLOAD` | raw auth payload hex (provider skipped); e.g. a synthetic keycard attestation from `tools/mint_attest.py` (`verify-local.sh` D8). A real card cannot be used in the container: no PC/SC, see recipe C |
| `CLIENT_IDENTITY_COMMITMENT` | the commitment a raw payload was minted for; empty = random per run |

| Last `RESULT:` line | Meaning |
|---|---|
| `CONNECTED — … refused this address; ask the operator to allowlist …` | **This is the goal for now.** libp2p dial + handshake with the pinned PeerId succeeded and the allocator's verifier ran. Exit 0. |
| `CONNECTED — … its eth allowlist is still empty …` | Same thing, before the operator added anyone. Exit 0. |
| `CONNECTED and ALLOWLISTED — … payer is not funded yet` | Also connected; your address was allowlisted and the allocator reached its registry. Exit 0. |
| `NO LIBP2P CONNECTIVITY …` | Could not dial/handshake. Check the multiaddr, that port 9000 on the allocator host is reachable from here (`nc -vz <ip> 9000`), and the allocator host's firewall. Exit 2. |
| `LOCAL FAILURE — …` | This side failed before dialling (producer module, malformed commitment / `CLIENT_AUTH_PAYLOAD`, conflicting options). Exit 1. |
| `GRANTED on the first attempt (the CLI deadline hid the reply; …)` | The first call answered nothing within logosctl's ~20 s deadline (normal on the hosted testnet: a registration takes longer than that); after `CLIENT_CONFIRM_WAIT_S` (120 s) the probe re-sent the same request and was refused `credential already used`, which proves the first one was granted. Exit 0. |
| `no reply twice (CLI deadline) — outcome unknown` | Neither call answered; ask the operator to look for the printed commitment in the allocator log. Exit 2. |
| `no reply within the CLI deadline …` | The allocator may still have granted: ask the operator to check its log for the printed commitment before retrying (a retry answers `credential already used` if it did). Exit 2. |

Re-run as often as you like; each run is a fresh request. `CLIENT_KEEP=1`
in `client.env` keeps the container up afterwards so you can poke at it:

```sh
docker compose -f client-compose.yml up -d client
docker compose -f client-compose.yml exec client logosctl status
docker compose -f client-compose.yml exec client logosctl --json call rln_sign_module identity '{"auth_type":"eth-allowlist"}'
docker compose -f client-compose.yml down
```

If you used the earlier `rln_sign_module` and want to keep its allowlisted
address, import its key into the new module (the old module's key file is
not read by `rln_sign_module`): put it in
`CLIENT_AUTH_ARGS={"private_key":"0x…"}`, or in a kept container run
`logosctl call rln_sign_module import_key '{"auth_type":"eth-allowlist","private_key":"0x…"}'`.
logos-allowlist has nothing to import (the key stays in your node).

## 5. Delivery mode (membership through the gifter, then delivery)

The probe (§4) sends one request with a random commitment, so the
membership it buys has no usable secret. Delivery mode is the product path:
the same image runs a long-lived `delivery-client` service that gets its RLN
membership through the allocator (delegated `register_membership` in
`liblogos_rln_module`, i.e. testers doc §2–§5 automated), then starts the
delivery module and USES the membership: a sender publishes a message with
an RLN proof, a receiver prints what arrives.

| Use | When |
|---|---|
| Probe (§4) | prove connectivity and the allowlist/credential path; nothing usable is kept |
| Delivery (§5) | you want a real membership, a running delivery node, and proof that RLN-proofed messages propagate |

Each grant spends about 74M of the allocator payer's balance; a restart does
not spend another (see Restart behaviour).

Files: `delivery-compose.yml` (project `rln-delivery-client`, service
`delivery-client`), `client-delivery.sh` (sourced by `client-entrypoint.sh`
when `CLIENT_MODE=delivery`, set by the compose file), `delivery.env.example`.

```sh
cp delivery.env.example delivery.env
$EDITOR delivery.env
docker compose -f delivery-compose.yml build
docker compose -f delivery-compose.yml up -d
docker compose -f delivery-compose.yml logs -f
```

### Variables in `delivery.env`

`delivery.env.example` lists every variable with a comment. Compose reads
`delivery.env` only for the container; `DELIVERY_HOST_TCP` and
`DELIVERY_HOST_DISCV5` are compose interpolation, so set them in the shell or
a `.env` file next to `delivery-compose.yml`, not in `delivery.env`.

Allocator and auth, reused from the probe:

| Variable | Default | Meaning |
|---|---|---|
| `ALLOCATOR_PEER_ID` | none (required) | the operator's `gifter_peer_id` |
| `ALLOCATOR_MULTIADDR` | `/ip4/<allocator host ip>/tcp/9000` (placeholder) | the operator's `gifter_multiaddr` (required); IPv4 only |
| `CLIENT_AUTH_TYPE` | `eth-allowlist` | `eth-allowlist`, `logos-allowlist`, `lez-allowlist`, `logos-pow-claim`, or `none` (open allocator) |
| `CLIENT_AUTH_PROVIDER` | `rln_sign_module` | producer module: `rln_sign_module` (every scheme but the PC/SC keycard) |
| `CLIENT_AUTH_ARGS` | empty | producer args (JSON object, or stringified). eth and lez: `{"private_key":"0x<32-byte hex>"}` for a stable allowlisted address / account id (imported, then not sent on); logos: `{"node_url":"http://host.docker.internal:18080"}`; logos/lez also take `"rate_max"` (default 100, ≥ `CLIENT_RATE`) and `"audience"` (default `""`, = the operator's `LOGOS_AUDIENCE` / `LEZ_AUDIENCE`); pow-claim: the pinned claim, see the block below |
| `CLIENT_AUTH_PAYLOAD` | empty | precomputed hex payload instead of a producer; rarely useful here (this mode generates its own commitment, and an attestation is bound to one) |
| `CLIENT_RATE` | `100` | `rate_limit` of the membership (the allocator caps it) |

Registry and identifier:

| Variable | Default | Meaning |
|---|---|---|
| `REGISTRY_ID` | `logos:testnet:fd322d32a46ddf57eece9db8d68e9b722262d1f770760fca63b8cb9e7775b971` | hosted testnet registry the membership is bought on |
| `RLN_IDENTIFIER` | `5e269b6a19fce081f5808b13442dcbc3522197638dd38df5a28bc4e55236b977` | application scope of the proofs (the `logos.test` identifier); must match every peer. Passed to logosctl as an `@file` (`rln-id.arg`) |
| `EPOCH_SIZE_SEC` | `600` | epoch length given to rln `start`; must match the preset (`logos.test`: 600) |
| `LEZ_RLN_SEQUENCER` | `https://testnet.lez.logos.co/` | sequencer the lez wallet syncs against |
| `DELIVERY_REGISTER` | `1` | `1` = register through the allocator when no membership is active; `0` = never register |
| `REG_WAIT_S` | `600` | seconds to wait for a registration to go `active` before parking (it is still watched) |
| `WALLET_WAIT_S` | `900` | seconds to wait for the lez wallet to report `ready` (about 3 min measured) |
| `ROOTS_WAIT_S` | `300` | seconds to wait for a non-empty `get_valid_roots` after the wallet is ready |

Delivery node:

| Variable | Default | Meaning |
|---|---|---|
| `DELIVERY_PRESET` | `logos.test` when UNSET | delivery preset. Unset = `logos.test`; set but EMPTY (`DELIVERY_PRESET=`) = the flat two-node config (cluster `DELIVERY_CLUSTER_ID`, no discovery). An empty value in `delivery.env` therefore means flat, not the default |
| `DELIVERY_VALIDATE` | `0` | `1` = this node validates incoming RLN proofs. `logos.test` ships validation off, so without this a receiver accepts unproofed messages too. For the flat config the module default (validating) applies unless you set this explicitly |
| `DELIVERY_CLUSTER_ID` | `198` | cluster id of the flat config; ignored with a preset |
| `DELIVERY_EXTIP` | empty | public IPv4 to advertise (`nat extip:<ip>`); empty = `nat none` (outbound only). Keep the host ports at 30303/9000 when set: the node advertises its container ports |
| `DELIVERY_STATICNODES` | empty | static peers, comma-separated `/ip4/…/tcp/…/p2p/…` multiaddrs |
| `DELIVERY_TOPIC` | `/rln-gifter/1/delivery-demo/proto` | content topic both sides use |

Role and send:

| Variable | Default | Meaning |
|---|---|---|
| `DELIVERY_ROLE` | `receiver` | `receiver` (prints what arrives) or `sender` (publishes `DELIVERY_SEND`) |
| `DELIVERY_SEND` | empty | text the sender publishes; a `#n <time>` suffix keeps each send unique; empty = a default greeting |
| `DELIVERY_SEND_EVERY_S` | `0` | `0` = send once; N = send again every N seconds |

Operations:

| Variable | Default | Meaning |
|---|---|---|
| `DELIVERY_STATUS_EVERY_S` | `60` | status line, received-message and parked-reason interval, seconds |
| `DELIVERY_CONNECT_WAIT_S` | `600` | seconds the sender waits for a non-`Disconnected` connection status before its first send (then sends anyway) |
| `DELIVERY_EVENT_WAIT_S` | `90` | seconds to wait for each send's proof-request and `messagePropagated` events |
| `DELIVERY_RLN_READY_S` | `180` | seconds to wait for delivery's `rlnState` to report `Ready` after `createNode` |
| `CALL_TIMEOUT` | `60` | budget of one logosctl call, seconds (the CLI itself gives up after about 20 s) |
| `DELIVERY_HOST_TCP` | `30303` | compose only: host port for 30303 tcp+udp |
| `DELIVERY_HOST_DISCV5` | `9000` | compose only: host port for 9000/udp |

### Startup milestones

In `docker compose -f delivery-compose.yml logs -f`, in order (strings as
printed by `client-delivery.sh`):

1. `rln presets: shipped logos.test (validation off)` or `rln presets:
   /var/lib/allocator-client/rln-presets.json (preset '…', validation N): …`,
   then `modules: …` (libp2p, lez, rln, gifter, the producer unless the
   payload is raw or registering is off, delivery last) and, for
   eth-allowlist, `eth-allowlist address (the operator allowlists this): 0x…`;
2. `rln module started on <registry> (epoch 600s, provision off)`;
3. wallet: `wallet_status: …` lines; if it says "no network selected" the
   script runs `use_network testnet` (`wallet unbound: use_network … -> …`);
   then `wallet ready after N s` (about 3 min). Registration waits for this
   and for the roots (`registry read path warm after N s`), otherwise its
   300 s confirmation window is spent on the wallet sync;
4. `membership state at start: unknown` (fresh volume), `libp2p peer id …`,
   `register_membership -> <peer> @ <multiaddr> (<type> via <producer>, rate N)`,
   `register_membership accepted: …`; an empty reply prints
   `register_membership: no reply within the CLI deadline; not re-sending, polling the state`;
5. `waiting for the membership to go active (budget 600s)`, `membership
   state: pending`, then `membership active at leaf N (identity commitment
   …, registry …)` (about 90-120 s);
6. `delivery createNode: …`, `rlnState: …`, `rlnState Ready (scope …)`;
7. `delivery peer <id>` and `delivery multiaddrs …`; then `subscribed to
   <topic> as <role>`;
8. sender only: `waiting for a delivery connection (budget 600s)`,
   `connection status: …`, `letting the relay mesh settle (15 s)`, `send #1
   on <topic>: request … ("…")`, `proof generation requested: …`, then
   one of
   - `RESULT: SENT WITH RLN PROOF hash=<h> quota a→b leaf N` (success: the
     proof request and `messagePropagated` were seen and the quota dropped);
   - `RESULT: PROPAGATED WITHOUT A PROOF REQUEST hash=<h> quota a→b leaf N`
     (the message went out but no proof generation was observed: the proof
     is NOT demonstrated);
   - `RESULT: NOT PROPAGATED request … within 90s …` or
     `RESULT: SEND FAILED: …` (failure);
9. status loop, one line per `DELIVERY_STATUS_EVERY_S`:
   `status: <role> conn=… membership=… leaf=… quota=rem/limit received=N
   validated=N sent=N peer=<delivery peer id>`. On the receiver each
   arriving message prints `RECEIVED hash=… topic=… source=… payload=…`;
   `validated` counts the RLN validate-proof requests seen. Connecting to the
   public fleet can take minutes.

With `DELIVERY_REGISTER=0` and no membership a receiver does not register: it
prints `no membership and DELIVERY_REGISTER=0: receiving only. delivery's rln
start may park an awaiting_funding task on this payer — never fund it` and
carries on as a receive-only node. A sender in that state parks.

### Restart behaviour

- A restart never mints a new identity. An `active` (or `grace_period`)
  membership is reused and registration is skipped (`membership state at
  start: active`); `pending` is polled to `active`.
- A previous `failed` membership is registered again only if the reason
  spent no grant (not allowlisted, empty allowlist, `insufficient_balance`,
  claim not final, `protocolRequest:` errors) and `DELIVERY_REGISTER=1`;
  the log says `previous registration failed without spending a grant
  (<reason>): registering again`.
- Anything else PARKS: the container stays up, writes the reason to
  `parked.txt` on the volume and prints `PARKED: <reason>` and then
  `PARKED (membership …): <reason>` on every status tick. It never registers
  again by itself. Examples: `membership failed: credential already used —
  not re-registering (a grant may be spent; manual review)`;
  `registration failed: confirmation_window_elapsed — the grant may be spent;
  not re-registering (manual review: logosctl call liblogos_rln_module
  get_memberships <registry>)`; a non-consuming failure
  (`registration failed without spending a grant: … — fix it on the allocator
  side, then restart this container to register again`);
  `membership still pending after 600s; watching for it to go active`;
  `register_membership refused before submitting: …`. If the membership
  turns `active`/`grace_period` while parked the container prints
  `membership is now active — leaving park` and carries on. A
  `confirmation_window_elapsed` after the allocator paid is a spent grant:
  tell the operator, do not retry blindly.
- If the daemon is gone for three status ticks (`daemon status reports no
  running daemon (miss n/3)`) the container exits 1 and
  `restart: unless-stopped` brings it back; an active membership is not
  registered again.
- Compose gives the container a 75 s `stop_grace_period` (a logosctl call in
  flight, up to `CALL_TIMEOUT`, delays the TERM trap that stops the daemon),
  and caps the container log at 10 MB x 5 files.

### The `delivery-data` volume

`delivery-data` (compose volume `rln-delivery-client_delivery-data`, mounted
at `/var/lib/allocator-client`) holds the logosctl session, so: the RLN
keystore (`liblogos_rln_module/<instance>/rln_sealed.json` and friends) which
IS the membership secret, the lez wallet home, the event logs
(`events-<module>.jsonl`, one per watched module), `registrations.jsonl` (one
line per registration reaching `active`: time, state, leaf index, identity
commitment), `sends.jsonl` (one line per send: request id, hash, whether a
proof was requested, quota before/after, payload), `rln-id.arg`, the presets
file when one is needed, and `parked.txt` while parked. Treat it like a
private key. Back it up:

```sh
docker run --rm -v rln-delivery-client_delivery-data:/d -v "$PWD":/o debian tar czf /o/delivery-data.tgz -C /d .
```

`docker compose -f delivery-compose.yml down -v` DESTROYS the volume and with
it the membership (the grant is spent, a new one needs a fresh credential).
Plain `down` / `up` keeps it.

### Ports

The service publishes 30303 tcp+udp (delivery) and 9000 udp (discv5), as
`${DELIVERY_HOST_TCP:-30303}` and `${DELIVERY_HOST_DISCV5:-9000}` on the
host. The allocator listens on host 9000/tcp, so it does not clash with the
9000/udp mapping and both can run on one host. Everything the container
dials is IPv4 only: nim-libp2p cannot resolve `/dns4` in the container, so
every multiaddr (`ALLOCATOR_MULTIADDR`, `DELIVERY_STATICNODES`) must be
`/ip4/…`. On the allocator's own host dial the Docker host gateway IPv4
(`getent ahostsv4 host.docker.internal`, e.g. `192.168.65.254`), never the
name.

### Ready-made env blocks

`delivery.env.example` ends with the same three blocks, commented out;
uncomment one (later lines win over the defaults above it). Flat blocks must
keep `DELIVERY_PRESET=` set-but-empty.

Pow-claim (sender):

```
ALLOCATOR_PEER_ID=16Uiu2HAkwLPo…
ALLOCATOR_MULTIADDR=/ip4/<allocator public ip>/tcp/<port>
CLIENT_AUTH_TYPE=logos-pow-claim
CLIENT_AUTH_PROVIDER=rln_sign_module
CLIENT_AUTH_ARGS={"node_url":"http://host.docker.internal:8080","audience":"","rate_max":100,"claim_block_id":"<hex>","pow_nullifier":"<hex>"}
DELIVERY_ROLE=sender
DELIVERY_SEND=hello from the pow node
```

eth-allowlist on the LAN (receiver):

```
ALLOCATOR_PEER_ID=16Uiu2HAkwLPo…
ALLOCATOR_MULTIADDR=/ip4/<allocator host ip>/tcp/9000
CLIENT_AUTH_TYPE=eth-allowlist
CLIENT_AUTH_PROVIDER=rln_sign_module
CLIENT_AUTH_ARGS={"private_key":"0x<fresh key>"}
DELIVERY_ROLE=receiver
```

On the allocator's own host use the Docker host gateway
(`/ip4/192.168.65.254/tcp/9000`). First print the key's address with one
probe run (refused "not allowlisted", nothing spent) and have the operator
allowlist it.

Flat two-node stretch (no public fleet; both nodes `DELIVERY_PRESET=` and
`DELIVERY_VALIDATE=1`; B's 30303 must be reachable from A, which dials it as a
static peer):

```
DELIVERY_PRESET=
DELIVERY_VALIDATE=1
DELIVERY_STATICNODES=/ip4/<peer ip>/tcp/30303/p2p/<peer id>
```

### What each verification run proves

| Run | Setup | Proves |
|---|---|---|
| 1 | A sender (pow-claim) and B receiver (eth-allowlist), `logos.test`, validation off | A's membership came through the gifter, its delivery node generated an RLN proof with it (quota a→b drops by one) and the message propagated to B over the public fleet: `RECEIVED hash=…` on B equals the hash in A's `RESULT:` |
| 1b | as 1, B restarted with `DELIVERY_VALIDATE=1`, A resends | B emits `dispatchRlnValidateProofRequestEvent` before `messageReceived`: the proof was actually validated. Without `DELIVERY_VALIDATE=1`, `logos.test` does no validation, so run 1 alone does not prove it |
| 2 (stretch) | plain two-node flat config, validation on, A dials B via `DELIVERY_STATICNODES` (B's 30303 must be reachable from A) | the same without the public fleet |

The delivery PeerId may change when the node is recreated; re-copy it from B's
`delivery peer` log line into A's `DELIVERY_STATICNODES` if the dial fails.
