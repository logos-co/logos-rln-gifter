# rln-sign-module — the producer

The produce half of every auth vector that needs no card hardware, in one
module, so a client module can drive any of them through
`auth_provider`. `produce_auth(args_json)` takes the `auth_vector`
ProduceRequest `{"auth_type","domain","action_hex","args"?}`
and returns `{"payload_hex"}` or `{"error"}`. `auth_type` is
`<scheme>-<authoriser>` over the schemes `eth`, `lez`, `logos`, `peer` and
the authorisers `allowlist`, `any`, `pow-claim` (logos only); the keycard
scheme is `../keycard-capture-module`. `domain` is the service's
(`rln-membership` for a membership allocation) and `action_hex` the 32-byte
action digest the service computes over the request (64 hex, optional
`0x`). Together with `args.audience` (default `""`) they are what the
payload is bound to, so a payload made for one service, action or provider
verifies nowhere else. `args` may be an object or a string holding one.

| scheme | key | `args` | identity (`identity`) |
|---|---|---|---|
| `eth` | module-owned secp256k1 key, or `args.private_key` | `audience`?, `private_key`? | `0x…` address |
| `lez` | module-owned LEZ account key, or `args.private_key` | same | account id (hex + base58) |
| `logos` | the node's KMS key (`POST /wallet/sign/zk`) | `node_url`? (default `http://127.0.0.1:8080`), `public_key`?, `http_timeout_ms`?, `audience`? | key K |
| `peer` | none: the payload is empty and the verifier takes the identity from its transport | — | `args.peer_id` (the node's own, from `libp2p_module.peerInfo`) |

eth signs EIP-191 over the text `Logos <domain> authorisation: 0x<digest>`,
which any wallet can sign too. `pow-claim` adds the claim locator from the
same node (`claim_address`, `claim_block_id`, `pow_nullifier`,
`exclude_nullifiers`, … — see logos-paymaster-crates `crates/pow-claim`); the
key the claim is searched for is `claim_address`, else `public_key`.

- `identity` `{"scheme"|"auth_type","args"?}` → `{"scheme","id","persisted"}`
  (+ `id_base58` for lez, `source` for logos and peer, `auth_type` when the
  request named one). Generates and persists the eth/lez module key on
  first use.
- `import_key` `{"scheme"|"auth_type","private_key","force"?}` replaces the
  eth or lez module key; a different persisted key needs `force:true`.

Key custody is demo-grade on purpose: one plaintext hex file per scheme
under the module's host-stamped persistence path (0600); a host that stamps
no path gets in-memory keys that change per run.

The rules every composition shares (the payload layout, the binding digest,
the eth text) are in logos-paymaster-crates `docs/auth-vectors.md`; the
pieces are its `crates/auth-vectors`.

Build: `nix build 'path:.#lgx'` (delete `rust-lib/target` first). Local
tests: `cargo test` in `rust-lib` (no network). The crates are pinned by git
rev from logos-paymaster-crates, which nix fetches from GitHub.
