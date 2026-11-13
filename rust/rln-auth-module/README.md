# rln-auth-module — the gifter's verifier

One module answers every auth vector an allocator can be configured with.
The allocator calls `verify_auth(args_json)` with the `auth_vector`
(contract v3) VerifyRequest
`{"auth_type","payload_hex","domain","action_hex","config"?,"peer_id"?}`.
`auth_type` is a composition, `<scheme>-<authoriser>`, and the module
resolves both halves from the registry it builds at load (`auth_vectors`).
`domain` is the calling service's (`rln-membership` for the membership
allocator) and `action_hex` the 32-byte action digest it computed over the
request; the payload must be bound to both, and to `config.audience`. The
reply is `{"ok":true,"identity","scheme","nullifier"}`,
`{"ok":false,"reason"}`, or `{"error"}` for a malformed request, an invalid
domain, an unknown composition or a bad config. `supported_auth_types()`
lists the twelve compositions.

| scheme | identity | authoriser | config | nullifier |
|---|---|---|---|---|
| `eth` | recovered 0x address (EIP-191 over `Logos <domain> authorisation: 0x<digest>`) | `allowlist` / `any` | `{"allowlist":["0x…"],"audience"?}` / `{"audience"?}` | address |
| `lez` | LEE account id of the BIP-340 key | `allowlist` / `any` | `{"allowlist":["<64 hex or base58>"],"audience"?}` / `{"audience"?}` | account hex |
| `logos` | zkSign key K | `allowlist` / `any` / `pow-claim` | `{"allowlist":["<64 hex K>"],"audience"?,"zksign_vk_path"?}` / `{"audience"?}` / `{"node_url",…}` | hex K / hex K / hex(pow_nullifier) |
| `keycard` | card identity key | `allowlist` / `any` / `attestation` | `{"allowlist":["<33-byte hex>"]}` / `{"audience"?}` / `{"trusted_cas":["<33-byte hex>"],"audience"?}` | ident_pub hex / ident_pub hex / keccak(ident_pub) |
| `peer` | the requester's peer id, from the request's `peer_id` (the transport's) | `allowlist` / `any` | `{"allowlist":["<peer id>"]}` / `{}` | peer id multihash hex |

The rules every composition shares (the payload frame `03 ‖ part ‖
evidence`, the binding digest under `logos/auth/<domain>/<auth_type>/3`,
reject-vs-error) are in logos-paymaster-crates `docs/auth-vectors.md`. The
pieces themselves live in its `crates/auth-vectors`; this module only
composes them.

Build: `nix build 'path:.#lgx'` (delete `rust-lib/target` first). Local
tests: `cargo test` in `rust-lib` (no network). The crates are pinned by git
rev from logos-paymaster-crates, which nix fetches from GitHub.
