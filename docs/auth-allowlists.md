# The allowlist authoriser, per scheme: eth, logos, lez, keycard

The allocator operator keeps a list of identities; a tester proves, with a
signature bound to THIS request's identity commitment, that they hold one.
The identity is the nullifier, so each listed entry yields exactly one
membership. The pipeline, the binding digest, the payload frame and the
reasons are in [`auth-vectors.md`](auth-vectors.md); this page is what an
operator and a tester do per scheme.

One module per side serves every composition: the verifier `rln_auth_module`
(`rust/rln-auth-module`; each `auth_type` keeps its own config entry in
`authVerifiers`) and the producer `rln_sign_module` (`rust/rln-sign-module`;
the keycard scheme's producer is `keycard_capture_module`). The producer's
methods:

- `produce_auth(args_json)`: the `rln_auth_vector` ProduceRequest
  `{"auth_type","id_commitment_hex","args"?}` -> `{"payload_hex"}`.
- `identity(req_json)`: `{"scheme"|"auth_type","args"?}` ->
  `{"scheme","id","persisted"}`, plus `id_base58` (lez) or `source` (logos).
  `id` is what the operator allowlists. The eth/lez module key is generated
  on first use.
- `import_key(req_json)`: `{"scheme":"eth"|"lez","private_key":"0x…","force"?:true}`
  -> the identity object, after persisting the key. A different key already
  persisted for that scheme is kept and the import refused unless
  `"force": true` replaces it. logos is refused (the key lives in the node's
  KMS); keycard has no key to import.

Every reply can be `{"error":"…"}` instead.

Common rules:

- The verifier config is `{"allowlist": [...], "audience"?: ""}`. A missing or
  empty allowlist is an operator error (`allowlist is empty`), never a silent
  accept; one malformed entry rejects the whole list, named with its text.
- The allowlist is checked BEFORE the signature for every scheme whose part
  carries the key (logos, lez, keycard): an unlisted identity is refused by
  name without signature work. eth's identity is only known after recovery.
- `rate_max` and `audience` come from the producer's `auth_args`
  (`{"rate_max": 100, "audience": ""}` by default); `rate_max` travels in the
  payload, `audience` is the verifier's `config.audience` (the Docker
  allocator sets `LOGOS_AUDIENCE` / `LEZ_AUDIENCE`). eth binds neither
  (`auth-vectors.md` §4).

## Summary

| | `eth-allowlist` | `logos-allowlist` | `lez-allowlist` | `keycard-allowlist` | `peer-allowlist` |
|---|---|---|---|---|---|
| Who holds the key | the module on the tester's client (`eth_sign_key.hex`, 0600, under the module's persistence dir), or any wallet | the tester's own logos-blockchain node (its PoWClaim key); nothing is stored in the module | the module on the tester's client (`lez_sign_key.hex`, 0600) | the card | the client's `libp2p_module` (its node key; nothing is signed) |
| Producer `auth_args` | `private_key`? | `node_url`, `public_key`?, `http_timeout_ms`?, `rate_max`, `audience` | `private_key`?, `rate_max`, `audience` | `rate_max`, `audience` | `rate_max` (the payload is the bare frame; `identity` needs `peer_id`) |
| Allowlist entry | `0x` + 40 hex address (the Docker reader accepts it without `0x` or in mixed case) | 64 hex public key K (little-endian, as the node prints it); `0x` and uppercase accepted | 64 hex account id, or its base58 form | 66 hex compressed identity key | the PeerId as libp2p prints it (base58) or its multihash hex |
| Nullifier | the address | K | the account id, 64 hex | the identity key, 66 hex | the multihash, lowercase hex |
| Operator file (Docker) | `config/allowlist.txt` | `config/allowlist-logos.txt` | `config/allowlist-lez.txt` | (not served by the Docker allocator yet) | (not served by the Docker allocator yet) |
| Tester recipe | testers doc A | testers doc D | testers doc E | — | — |

## eth

- `identity` with `{"scheme":"eth"}` -> `id` = the lowercase `0x` address.
  `auth_args` `{"private_key":"0x<32-byte hex>"}` signs with that key instead.
  Any wallet's `personal_sign` over the lowercase hex of the commitment works
  too, framed as `02 ‖ sig ‖ rate_max LE` and sent as `authPayload`.
- Verifier config: `{"allowlist":["0x…"]}`.
- Refusals: `signature verification failed`, `address not allowlisted`,
  `allowlist is empty`.

## logos

- The key is a logos-blockchain node's PoWClaim key. The node zkSigns the
  binding digest on request (`POST /wallet/sign/zk`, about 15 s); the private
  key never leaves the node.
- `identity` with `{"scheme":"logos","args":{"node_url":…}}` -> `id` = K and
  `source` = `args` or `pow_status` (the node's single PoWClaim target; zero or
  several targets need `public_key` in the args); `persisted` is always true.
  `auth_args`: `{"node_url":"http://127.0.0.1:8080","public_key"?,"http_timeout_ms"?,"rate_max"?,"audience"?}`.
  From the Docker client the node is `http://host.docker.internal:18080`.
- Verifier config: `{"allowlist":["<64 hex K>", …],"audience":""}`;
  `zksign_vk_path` optionally replaces the bundled verification key. An entry
  that is not a canonical little-endian BN254 scalar rejects the whole config
  (`big-endian paste?`).
- K is the hex `/pow/status` prints (a little-endian field element)
  everywhere; it is never reversed. The zero key is refused.
- Refusals: `public key not allowlisted`, `allowlist is empty`,
  `zkSign signature invalid (…)`.

## lez

- The key is a plain secp256k1 key held by `rln_sign_module`. The account id
  is `sha256(LEE_PREFIX ‖ xonly)` over the x-only public key, the same
  derivation as a LEZ account; the base58 form is what a LEZ wallet shows.
  Importing the same private key into a LEZ wallet yields the same account.
- `identity` with `{"scheme":"lez"}` -> `id` (hex) and `id_base58`;
  `auth_args` `{"private_key"?,"rate_max"?,"audience"?}`. Without a persistence
  path the key is per-run; use the override for a stable id.
- Verifier config: `{"allowlist":["<64 hex or base58>", …],"audience":""}`,
  entries normalised to hex.
- Refusals: `account not allowlisted`, `allowlist is empty`,
  `signature verification failed`.

## keycard

- The card's identity key (`ident_pub`, survives factory reset) is the
  identity; `keycard_capture_module` produces the part over PC/SC. The same
  card can also be judged by its CA instead (`keycard-attestation`,
  `auth-vectors.md` §2).
- Verifier config: `{"allowlist":["<66 hex compressed key>", …]}`.
- Refusals: `card not allowlisted`, `attestation parse failed: …`,
  `attestation verification failed: …`.

## peer

- No key on the client beyond its libp2p node's: the gifter reads the
  requester's peer id off the accepted stream (`libp2p_module` ≥ 1.1.0) and
  that is the identity. The payload is the bare frame (`02 ‖ rate_max LE`,
  `rln_sign_module.produce_auth` makes it, or `authPayload:
  "026400000000000000"` for rate_max 100 by hand).
- `identity` with `{"scheme":"peer","args":{"peer_id":"<from libp2p_module.peerInfo>"}}`
  -> `id` = the multihash hex an operator allowlists; `peer-any` needs no list.
- Verifier config: `{"allowlist":["12D3Koo…" | "<hex>", …]}`; `peer-any`
  takes `{}`.
- Refusals: `peer not allowlisted`, `allowlist is empty`; a gifter whose
  bridge reports no peer id answers `{"error":"transport peer id unavailable…"}`.

## Docker allocator

Files in `tools/allocator/docker/config/` (bind-mounted at `/etc/allocator`,
live files git-ignored, examples `*.txt.example`): lines are `#` comments or one
credential. `allowlist.txt` lines must match `(0x)?[0-9a-fA-F]{40}` (normalised
to lowercase with `0x`). `allowlist-logos.txt` lines must match
`(0x)?[0-9a-fA-F]{64}` (normalised to lowercase without `0x`) and be a canonical
little-endian field element (< the BN254 modulus; a big-endian paste usually is
not). `allowlist-lez.txt` lines are 64 hex, or base58 that the reader decodes and
keeps only if it is exactly 32 bytes; both are passed to the verifier as
lowercase hex. Other lines are dropped and logged (the verifier would reject the
whole list for one bad entry), and duplicates are dropped. `LOGOS_AUDIENCE` /
`LEZ_AUDIENCE` (default empty) become the verifiers' `config.audience`; testers
must put the same string in `auth_args.audience`. The entrypoint watches the
three files by mtime and re-serves within `HEALTH_EVERY_S` (30 s) when any
changes. `LOGOS_ALLOWLIST=0` / `LEZ_ALLOWLIST=0` turn a type off; both are on
by default and served even when empty (with a WARNING in the log). Paths can
be overridden with `ALLOWLIST_LOGOS_FILE` / `ALLOWLIST_LEZ_FILE`.
