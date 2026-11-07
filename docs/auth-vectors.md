# Auth vectors — the one pipeline, and the pieces it is composed of

Normative for every auth vector the RLN gifter speaks. The Rust types in
`crates/rln-auth-vector` are the reference; a module in another language
conforms by speaking the same JSON and bytes.

## 1. The contract

A vector module exposes one or both of two methods, each taking ONE
JSON-string argument and returning a JSON string:

| Method | Side | In | Out |
|---|---|---|---|
| `produce_auth` | client | `{"auth_type","id_commitment_hex","args"?}` | `{"payload_hex"}` |
| `verify_auth` | gifter | `{"auth_type","payload_hex","id_commitment_hex","rate","config"?,"peer_id"?}` | `{"ok","reason"?,"nullifier"?}` |

- `args` is the requesting application's opaque material, forwarded verbatim
  (it may arrive as a string holding JSON): the binding's `rate_max` and
  `audience`, plus whatever the signer and claimant need.
- `config` is the gifter operator's per-type configuration from the
  `authVerifiers` serve entry, passed on every call; verifiers stay stateless.
- `rate` is the rate the gifter settled on for this request (it clamps to
  the registry's `maxRateLimit` BEFORE calling the verifier).
- `peer_id` is the requester's libp2p peer id as the gifter's transport
  authenticated it (`libp2p_module` ≥ 1.1.0 reports it with the accepted
  stream). A scheme that signs nothing proves its identity from it.
- A refusal is `{"ok": false, "reason": …}` — still a successful call. The
  `{"error": "…"}` envelope is for a malformed request, an unknown
  composition, or an operator mistake (bad config, unreachable node).
- A `nullifier` (any stable lowercase string naming the spent credential) opts
  the credential into the gifter's shared replay protection: reserved before
  the on-chain register, rolled back when nothing was submitted, persisted to
  the consumed-nullifier file otherwise, under the key
  `<registry>:<auth_type>:<nullifier>` (the registry's config account as
  lowercase hex) — a credential buys one membership per registry.

## 2. Composition: `auth_type = <scheme>-<authoriser>`

An `auth_type` is not a name from a list; it is two pieces joined by the
FIRST dash. A **scheme** is how a digest gets signed and which identity that
proves. An **authoriser** is how an identity gets accepted and what evidence
that takes. A module composes the pieces it ships into a registry and
answers every `auth_type` whose halves exist and are compatible.

| scheme | signs with | identity (`canonical`, what an allowlist holds) |
|---|---|---|
| `eth` | secp256k1 recoverable ECDSA, EIP-191 (the exception, §4) | recovered address, lowercase `0x` + 40 hex |
| `lez` | BIP-340 Schnorr by a LEZ public-account key (x-only) | LEE account id `sha256("/LEE/v0.3/AccountId/Public/\0\0\0\0\0" ‖ xonly)`, 64 hex (base58 accepted on input) |
| `logos` | a logos-blockchain node's zkSign (Groth16) by its KMS key K | K, 64 hex little-endian Fr, a canonical scalar (as `/pow/status` prints it) |
| `keycard` | a Keycard's identity key over IDENTIFY_CARD | the card's compressed identity key, 66 hex |
| `peer` | nothing: the libp2p secure channel the request arrived on proved the requester's key (§3.3) | the peer id's multihash, lowercase hex (base58 `12D3Koo…`/`16Uiu2…` accepted on input) |

| authoriser | accepts | config | evidence bound | nullifier |
|---|---|---|---|---|
| `allowlist` | any scheme | `{"allowlist":[<identity>…],"audience"?:""}` | none | the identity |
| `any` | any scheme | `{"audience"?:""}` | none | the identity (one membership per identity per registry) |
| `attestation` | `keycard` | `{"trusted_cas":[<33-byte hex>…],"audience"?:""}` | none (the CA cert travels in the keycard part) | `keccak256(ident_pub)`, once per card |
| `pow-claim` | `logos` | `{"node_url","audience"?,"min_payout"?,"allow_direct_ownership"?,"allow_spend_locator"?,"http_timeout_ms"?,"audit_log"?}` | the claim locator; its `pow_nullifier` is in the digest | `hex(pow_nullifier)`, once per claim |

The twelve compositions this repo ships: `eth-allowlist`, `eth-any`,
`lez-allowlist`, `lez-any`, `logos-allowlist`, `logos-any`,
`logos-pow-claim`, `keycard-allowlist`, `keycard-any`,
`keycard-attestation`, `peer-allowlist`, `peer-any`.
`rln_auth_module.supported_auth_types()` lists them; an `auth_type` whose
halves do not compose (`eth-attestation`, `lez-pow-claim`) is an
`{"error"}`. `peer-any` is the open-but-once vector: any libp2p peer may
claim, one membership per peer id per registry, with no key material on the
client beyond its libp2p identity.

## 3. The pipeline

Produce: parse `auth_type` → resolve signer + claimant → **binding** from the
request and `args` → **evidence** = claimant gathers → **digest** →
**scheme part** = signer signs → **frame**.

Verify: parse `auth_type` → resolve scheme + authoriser → configs → hex →
**unframe** → scheme decodes its part (and names the identity it claims, when
the part carries a key) → authoriser decodes its evidence (nothing may trail)
→ binding from the request, the payload's `rate_max` and the configured
`audience` → `rate ≤ rate_max` → [authorise the claim first, when the
authoriser says so: an allowlist is cheaper than a signature] → digest →
scheme verifies the signature and yields the PROVEN identity → it must equal
the claimed one → [authorise the proven identity otherwise] → accept with the
authoriser's nullifier.

### 3.1 The binding and its digest

```
Binding { id_commitment: 32 bytes LE (a canonical BN254 scalar),
          rate_max: u64 (args, default 100),
          audience: string ≤ 255 bytes (args / config, default "") }

digest = sha256( "logos/rln/<auth_type>/2"
               ‖ id_commitment
               ‖ rate_max as u64 little-endian
               ‖ u8 len(audience) ‖ audience
               ‖ extra )                      // the authoriser's bound evidence
```

The domain is derived from the composed `auth_type`, so a signature for one
composition is never a signature for another. `extra` is empty for
`allowlist` and `attestation`; for `pow-claim` it is the 32-byte
`pow_nullifier`.

- The verifier refuses `rate <rate> exceeds the signed rate_max <rate_max>`.
- The verifier's `config.audience` must equal the producer's `args.audience`:
  a payload made for one allocator is refused by another.

### 3.2 The frame

```
payload = version(1) = 0x02 ‖ scheme part ‖ authoriser evidence ‖ rate_max u64 LE(8)
```

Each part is sized by its own decoder:

| scheme | part |
|---|---|
| `eth` | 65 B `r ‖ s ‖ recid` (recid 0/1 on produce; 27/28 accepted on verify; low-S only) |
| `lez` | 96 B `xonly(32) ‖ BIP-340 sig(64)` |
| `logos` | 160 B `K(32) ‖ zksig(128)` (`pi_a ‖ pi_b ‖ pi_c`, compressed Groth16) |
| `keycard` | the IDENTIFY_CARD TLV `A0 { 8A cert(98) = ident_pub(33) ‖ ca_sig(65), DER sig }`, self-sized |
| `peer` | empty |

| authoriser | evidence |
|---|---|
| `allowlist`, `any`, `attestation` | none |
| `pow-claim` | `flags(1) ‖ claim_block_id(32) ‖ pow_nullifier(32) ‖ [spend_block_id(32) ‖ spend_tx_hash(32)]` (bit 0 of flags = spend locator present; refused by the PoC verifier) |

A wallet signature or a minted attestation produced outside a producer module
is framed the same way before it is sent as a raw `authPayload`
(`tools/allocator/verify-chainless.sh`, `tools/mint_attest.py`).

### 3.3 The peer scheme: the stream is the binding

`peer` signs nothing. The gifter accepts the request on a libp2p stream
whose Noise handshake proved the remote holds the key behind its PeerId,
and the commitment arrives on that same stream, so the transport binds
commitment and identity; the verifier is handed the peer id in
`VerifyRequest.peer_id` and that is the proven identity. Nothing in the
payload is signed, so `rate_max` and `audience` are not bound (the frame's
`rate_max` still caps the settled rate), and a payload cannot be replayed
from another peer: the identity is the transport's, not the payload's. A
gifter whose libp2p bridge reports no peer id answers `{"error"}`
(`transport peer id unavailable`), never an accept.

## 4. The eth exception

The `eth` scheme signs the EIP-191 `personal_sign` envelope over the
LOWERCASE HEX of the bare 32-byte commitment (`keccak256("\x19Ethereum Signed
Message:\n64" ‖ hex(idc))`), NOT the binding digest, so any wallet can produce
it (`cast wallet sign --private-key … "<hex>"`). It therefore binds neither
`rate_max` nor `audience`: a leaked eth payload for a commitment the attacker
can register is spendable at any allocator that allowlists the address, at
any rate up to that allocator's `maxRateLimit`. The frame still carries
`rate_max`, and the nullifier still limits it to one membership per
allocator.

## 5. Reasons

Written once in `rln_auth_vector::reason`; the suites match on them:

| reason | when |
|---|---|
| `signature verification failed[: <detail>]` | the scheme's signature does not verify |
| `<noun> not allowlisted: <identity>` | allowlist; noun = `address` / `account` / `public key` / `card` |
| `rate <r> exceeds the signed rate_max <m>` | the settled rate is above the payload's |
| `payload hex: …`, `payload too short: …`, `payload version <v>, want 2`, `payload has <n> trailing bytes` | framing |
| `id_commitment must be 32 bytes, got <n>` | the request's commitment |
| `attestation parse failed: …`, `attestation verification failed: …` | keycard part / CA |
| `<noun> not allowlisted: <identity>` with noun `peer` | peer-allowlist |
| `evidence: …` | pow-claim locator |

Operator errors (`{"error"}`): `config.allowlist (array of …) is required`,
`config.allowlist is empty — nothing can verify`, `config.allowlist entries
must be strings`, a malformed entry named with its text, `config.trusted_cas
…`, `config.node_url is required`, `config.zksign_vk_path …`, `unknown
auth_type '<t>': …`, `transport peer id unavailable: …` (peer), and `node
unreachable or failing: …` from the pow-claim chain checks.

## 6. Where the code is

| | |
|---|---|
| `crates/rln-auth-vector` | the contract (§1), `AuthType`, `Binding` + `binding_digest`, the frame, the `Scheme` / `Authoriser` / `Signer` / `Claimant` traits and the `Transport` context (§3.3), the registries and the two flows (§3), the reasons (§5) |
| `crates/rln-auth-vectors` | the pieces of §2 and their produce halves (feature `sign`; `keycard-pcsc` for the card) |
| `crates/keycard-attest`, `crates/keycard-client` | the keycard TLV, CA recovery and PC/SC transport |
| `crates/zksign-light` | zkSign verification and the node's `/wallet/sign/zk` client |
| `crates/pow-claim` | claim discovery and the chain checks |
| `rust/rln-auth-module` | the gifter's verifier: every composition |
| `rust/rln-sign-module` | the client's producer: every composition but the PC/SC keycard |
| `rust/keycard-capture-module` | the keycard scheme's producer |

Operator guidance per scheme (what to allowlist, the Docker files): see
`docs/auth-allowlists.md`; the pow-claim design: `docs/auth-pow-claim.md`.

## 7. Developing the shared crates

The modules pin the shared crates by git tag (`auth-crates-v*`,
`keycard-crates-v*`). `.cargo/config.toml` at the repo root patches them to
`crates/` for every local `cargo` run; run `tools/dev/relock.sh` before
committing a module `Cargo.lock`, and bump the pins after pushing a new tag
(README, "Developing the shared crates").
