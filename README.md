# logos-rln-gifter

Gifted RLN membership allocation (LIP-158), packaged as two Logos modules. A
funded **gifter** node registers RLN memberships on-chain **on behalf of**
authenticated clients, so a client never holds funds or signs its own
registration — and its RLN identity secret never leaves its machine.

The protocol covers transport and authentication only. On-chain registration is
delegated to `liblogos_rln_module`; RLN proof generation and verification
(LIP-144) live elsewhere.

## Modules

- **`rln_gifter_module`** (`rust/rln-gifter-module`) — the gifter protocol,
  client and server, vector-agnostic, exposing two methods:
  - `request(args_json)` — client side. Takes the caller's RLN identity
    commitment (supplied by the RLN membership module, which keeps the
    identity secret), obtains the auth payload for the selected vector (raw
    `authPayload` or the `authProvider` module's `produce_auth`), sends the
    request to a gifter peer over `libp2p_module`, and returns the granted
    allocation. The identity secret never reaches this module.
  - `serve(args_json)` — gifter side. Mounts `/logos/rln/membership/1.0.0`,
    authenticates each request through the configured vector's `verify_auth`
    module, and registers the commitment on-chain via
    `liblogos_rln_module.register_member` on a single serialized worker.
- **Auth vector modules** — see [Authentication](#authentication):
  `keycard-capture-module` (producer, PC/SC — separate so a headless gifter
  needs no `pcsclite`; also `card_status()` for UIs), `keycard-auth-module`
  (verifier), `eth-auth-module` (verifier).
- **Crates** — `crates/rln-auth-vector` (the vector contract kit every
  module above and any third-party vector imports), `crates/keycard-attest`
  (attestation verify) and `crates/keycard-client` (PC/SC transport), all
  consumed as git dependencies (`keycard-crates-v0.1.0` tag / pinned rev).

The gifter modules drive `libp2p_module` through its generic custom-protocol
bridge (`protocolRequest`, `protocolAcceptStream`, `streamReadLpJson`,
`streamWriteLpJson`, `streamReleaseJson`); no gifter-specific code lives in
`libp2p_module`.

## Flow

```
client                                     gifter (funded wallet)
  |  request(...)                            |  serve(...)
  |  /logos/rln/membership/1.0.0             |
  |  RlnGifterRequest {                      |
  |    identityCommitment,                   |-- 1. authenticate (below)
  |    auth payload:  ---------------------> |
  |    per the selected auth vector          |-- 2. register_member on
  |  }                                       |      liblogos_rln_module, which
  |                                          |      funds and signs the tx
  |  RlnGifterResponse {                     |
  |    leafIndex, merkleRoot,      <-------- |
  |    blockNumber, transactionHash }        |
  '-- holds its idSecretHash + the gifted leafIndex
```

The request and response are length-prefixed protobuf on the
`/logos/rln/membership/1.0.0` stream.

## Authentication

The wire carries an opaque `(authentication_type, authentication_payload)`
pair, and **every auth vector is a plugin** — `rln_gifter_module` ships no
verification code of its own. The `crates/rln-auth-vector` kit defines the
contract both sides speak (see its README): a vector is a logos module
implementing `produce_auth` (client side — make the payload) and/or
`verify_auth` (gifter side — decide the request), and it plugs in with
configuration only:

- **Gifter node**: `serve`'s `authVerifiers` maps each accepted type to its
  verifier — `{"<type>": {"module": …, "config"?: {…}}}`. The opaque
  `config` rides along on every verify call, so verifiers stay stateless. A
  verdict `nullifier` opts the spent credential into shared replay
  protection: reserved before the on-chain register, rolled back on its
  failure, persisted to the append-only consumed-nullifier file on success.
  No `authVerifiers` = an open gifter.
- **Requester**: `request` takes `authType` plus either a raw `authPayload`
  (hex the application produced itself) or an `authProvider` producer module.
  No `authType` = an unauthenticated request.

Reference vectors in this repo:

- **Keycard attestation** (`keycard-auth-module` verifies,
  `keycard-capture-module` produces — split so a headless gifter never links
  PC/SC). The producer captures the raw `IDENTIFY_CARD` TLV, signed over the
  commitment-bound challenge
  `SHA256("logos/rln/keycard-attest/1" || id_commitment)`. The verifier
  recovers the vendor CA from the card certificate, checks it against
  `config.trusted_cas`, verifies the challenge signature, and returns the
  once-per-card nullifier `keccak256(ident_pub)` — stable across factory
  resets, so each card claims exactly one membership.
- **Eth allowlist / EIP-191** (`eth-auth-module` verifies; producing means
  `personal_sign`ing the lowercase hex of the 32-byte commitment with any
  wallet and passing it via `authPayload`). The verifier recovers the signer,
  checks `config.allowlist`, and returns the address as the nullifier — one
  membership per address, persisted like every other nullifier.

Authentication gates only the client↔gifter exchange; RLN proofs are untouched.

## Registration

The protocol never touches a chain itself. The gifter hands
`(identityCommitment, rateLimit)` to `liblogos_rln_module.register_member`,
which funds and signs the transaction, and relays the allocation (`leafIndex`,
`merkleRoot`, `blockNumber`, `transactionHash`) — or an error — back to the
client verbatim.

## Layout

| Path | What |
|---|---|
| `rust/rln-gifter-module/` | gifter module — `request` (client) + `serve` (server), wire codec, nullifier store, cross-module `lp_*` client; vector-agnostic |
| `rust/keycard-capture-module/` | keycard vector, producer half: client-side PC/SC capture (`produce_auth`) + `card_status` |
| `rust/keycard-auth-module/` | keycard vector, verifier half: attestation verify (`verify_auth`), no PC/SC |
| `rust/eth-auth-module/` | eth-allowlist vector, verifier half: EIP-191 recover + allowlist (`verify_auth`) |
| `crates/rln-auth-vector/` | the auth-vector contract kit: request/reply types, `AuthVector` trait, dispatch glue |
| `crates/keycard-attest/` | attestation verify: TLV parse, CA recovery, challenge binding, nullifier |
| `crates/keycard-client/` | PC/SC keycard transport: secure channel + `IDENTIFY_CARD` |
| `tools/mint_attest.py` | mint synthetic keycard attestations for CI / e2e (not for production) |
| `Cargo.toml` | workspace over `crates/*` |

## Build

Each module is a Logos cdylib module built with Nix, producing an `.lgx`:

```bash
nix build ./rust/rln-gifter-module#lgx
nix build ./rust/keycard-capture-module#lgx
```

The shared crates build as part of each module (fetched via the git dependency),
and can be checked on their own with `cargo test` from the repo root.

## Runtime requirements

- `rln_gifter_module` loads alongside `libp2p_module` (transport) and
  `liblogos_rln_module` (identity generation and on-chain registration). A gifter
  needs a funded wallet; a client needs neither funds nor a wallet.
- `keycard_capture_module` needs a PC/SC stack (`pcsclite`) and a card reader on
  the client.
