# tools/allocator — stand up an RLN membership allocator

The operator half of `docs/running-an-allocator.md` §6 as scripts: one
logoscore daemon hosting `libp2p_module` + `liblogos_lez_rln_module` +
`rln_gifter_module` (+ your verifier modules), with a **persisted libp2p
identity** so the PeerId you hand to clients survives restarts.

| File | What |
|---|---|
| `run-allocator.sh` | `up` / `serve` / `status` / `down`. Installs bundles, starts the daemon, loads modules in the required order, mints or reuses the node key (locally: `08021220` + 32 random bytes, the libp2p protobuf Secp256k1 envelope; `newPrivateKey` fails on some `libp2p_module` builds), brings libp2p up and **asserts** it listens on the configured address and, on a re-`up`, that the PeerId matches what `allocator.json` already published (`createNode` falls back to defaults silently), waits for the registry wallet, calls `serve`, writes `allocator.json`. |
| `verify-chainless.sh` | Proves everything short of the chain against the PoC's stub registry module and the real `rln_auth_module` verifier (see below). |
| `lib.sh` | daemon / module / libp2p / gifter helpers (vendored from `tools/pow-claim-poc/lib`, which vendored them from `logos-rln-e2e/harness/lib`). |

## Operator use

```sh
export LOGOSCORE=…/bin/logoscore
export LIBP2P_LGX=…/logos-libp2p_module-module-lib.lgx
export GIFTER_LGX=…/logos-rln_gifter_module-module-lib.lgx      # nix build ./rust/rln-gifter-module#lgx
export LEZ_RLN_LGX=…/logos-liblogos_lez_rln_module-module-lib.lgx
export EXTRA_LGX=…/logos-rln_auth_module-module-lib.lgx    # your verifier(s)
export EXTRA_MODULES=rln_auth_module

export ALLOCATOR_HOME=/var/lib/rln-allocator          # node_key.hex, consumed_nullifiers.txt, allocator.json, run/
export LISTEN_ADDR=/ip4/0.0.0.0/tcp/9000
export ADVERTISE_ADDR=/ip4/203.0.113.7/tcp/9000       # what clients dial; required when binding 0.0.0.0
export REGISTRY_CONFIG=<registry ConfigState account>
export KAD_BOOTSTRAP_NODES=/dns4/<host>/tcp/30303/p2p/<peerId>,…   # DHT peers to bootstrap from; empty = pinned peer id only
export PAYER=                                         # "" = the registry module's own payer
export AUTH_VERIFIERS='{"eth-allowlist":{"module":"rln_auth_module","config":{"allowlist":["0x…"]}}}'
export DAEMON_ENV="LEZ_RLN_SEQUENCER=https://… LEZ_RLN_TREE_ID_HEX=… LEZ_RLN_PAYER=… LEZ_RLN_PAYER_KEY=…"
export MIN_NATIVE_BALANCE=5000000000                  # wait until the payer holds this (fee reserve ≫ price)

tools/allocator/run-allocator.sh up        # prints allocator.json
tools/allocator/run-allocator.sh status
tools/allocator/run-allocator.sh serve     # refresh verifiers / wallet / cap on the running daemon
tools/allocator/run-allocator.sh down
```

The same variables can live in `$ALLOCATOR_HOME/allocator.env`; the
environment wins over the file. Every knob is documented in the script header.
`allocator.env.testnet-example` is a filled-in file for the hosted testnet
(LEZ v0.3.1, deployment testnet-v03-z3): copy it to the home, set the payer
key, and point the client's `registry_id` at the same config account.

`allocator.json` is the hand-off to your application's clients:

```json
{
  "gifter_peer_id": "16Uiu2HAm…",
  "gifter_multiaddr": "/ip4/203.0.113.7/tcp/9000",
  "registry_config": "…",
  "auth_types": ["eth-allowlist"],
  "open": false,
  "max_rate_limit": 100,
  "protocol": "/logos/rln/membership/1.0.0"
}
```

With `KAD_BOOTSTRAP_NODES` set, `up` creates the libp2p node with
`mountKad:true`, `mountServiceDiscovery:true` and those peers as
`bootstrapNodes`, and `serve` is sent `advertise:true` and
`advertiseAddrs:[ADVERTISE_ADDR]`: the allocator is published on the DHT and a
client finds it from the registry alone (`docs/running-an-allocator.md` §2.5).
`serve` waits up to 20 s for a connected peer before the first advertisement.
`allocator.env.testnet-example` lists the six logos.test fleet entry nodes.

Clients pass `gifter_peer_id` / `gifter_multiaddr` (plus `auth_type` and
`auth_payload` or `auth_provider`) as RegistryOptions to
`liblogos_rln_module.register_membership` with `delegated:"true"`; their
`registry_id` must name the same account as `registry_config`
(`docs/running-an-allocator.md` §5).

What the script does **not** do: fund the payer or keep its wallet at head.
Native balance arrives at genesis, over the bridge or by transfer (§3.3), and a
registration sent from a stale wallet is dropped silently. `up` waits for
`wallet_status` to be `ready` and, with `MIN_NATIVE_BALANCE`, for the balance;
keeping the wallet at head is the lez module's own job since 3.0.0 (it owns
the wallet; `wallet_status` reports its state). `serve` is
in-memory: after a daemon restart run `up` again (same home → same PeerId).

Open gifter (`AUTH_VERIFIERS` unset) is accepted with a warning: it pays for
every commitment it is sent.

## Chainless verification

```sh
tools/allocator/verify-chainless.sh      # ~1 min, two local daemons, writes runs/<ts>/summary.json
```

Prerequisites: a logoscore CLI and the libp2p + stub registry bundles from
`tools/pow-claim-poc/runs/artifacts.env` (or set `LOGOSCORE`, `LIBP2P_LGX`,
`STUB_LEZ_LGX`), `rust/rln-gifter-module/result-lgx`,
`rust/rln-auth-module/result-lgx` and
`rust/rln-sign-module/result-lgx` built (or `GIFTER_LGX`,
`ALLOWLIST_AUTH_LGX`, `ALLOWLIST_SIGN_LGX`), and Foundry's `cast` for the
externally signed EIP-191 cases. `LOGOS_NODE_URL` (a logos-blockchain node with
one PoWClaim key) enables A11.

It brings the allocator up through `run-allocator.sh` with
`liblogos_lez_rln_module` replaced by the PoC stub (whose `register_member`
answers non-JSON, so the gifter reports `NotSubmitted`) and asserts:

| | |
|---|---|
| A1 | `serve` mounts with a real `authVerifiers` entry |
| A2 | an unauthenticated request is refused: `unsupported authentication_type` |
| A3 | a garbage payload reaches the verifier and is rejected, not errored |
| A4 | a valid EIP-191 signature from a non-allowlisted key is rejected by address |
| A5 | a valid signature from the allowlisted key is accepted and reaches `register_member` exactly once; the nullifier is released on `NotSubmitted` |
| A6 | `down` + `up` on the same home yields the **identical PeerId** |
| A7 | a client still holding the old `(peer id, multiaddr)` is served after the restart |
| A8 | `serve` refresh to an open gifter: an unauthenticated request now reaches `register_member` |
| A9 | the **producer** path: the client daemon's `rln_sign_module.identity` id for eth-allowlist is allowlisted by a `serve` refresh, a request with `authProvider:"rln_sign_module"` (no payload, the module signs the commitment during the request) is accepted and reaches `register_member` once; a `cast`-signed foreign key is still refused |
| A10 | a commitment that is not a canonical BN254 scalar (and a zero one) is refused by the requester before any dial, `invalid_commitment: …`, and the registry module is never called |
| A11 | logos-allowlist (with `LOGOS_NODE_URL`): `identity` with `{"auth_type":"logos-allowlist","args":{"node_url":…}}` reads the node's key K; unlisted K is refused by name, listed K is accepted and reaches `register_member` |
| A12 | lez-allowlist: the module's lez key (`identity` → `id` + `id_base58`); unlisted refused by name, listed by base58 and then by hex both accepted. From A9 on every `serve` names `rln_auth_module` for each allowlist type it carries |

Not covered, by construction: the registration landing on a registry and the
client's `pending → active` confirmation. Those need a chain with a funded
payer. The logos-rln-e2e scenario `rln-allocator` (branch `feat/rln-allocator`
on the v0.3.0 relock) covers exactly that leg for this shape of allocator:
persisted key, eth-allowlist verifier, restart with the same PeerId, two
registrations paid by the gifter, and the registry-mismatch negative.
`consumer-gifter` and `chat-basecamp-gifter` cover an open, loopback,
fresh-identity gifter.
