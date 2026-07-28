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
  client and server, exposing two methods:
  - `request(args_json)` — client side. Takes the caller's RLN identity
    commitment (normally supplied by the RLN membership module, which keeps
    the identity secret; a legacy `seed` argument instead derives one via
    `liblogos_rln_module.generate_identity`), optionally captures a Keycard
    attestation bound to it, sends the request to a gifter peer over
    `libp2p_module`, and returns the granted allocation. The identity secret
    never reaches this module.
  - `serve(args_json)` — gifter side. Mounts `/logos/rln/membership/1.0.0`,
    authenticates each request, and registers the commitment on-chain via
    `liblogos_rln_module.register_member` on a single serialized worker.
- **`keycard_capture_module`** (`rust/keycard-capture-module`) — client-side
  PC/SC [Keycard](https://keycard.tech) capture, a separate module so a headless
  gifter needs no `pcsclite`. Methods:
  - `capture_attestation(id_commitment_hex)` — connect / select /
    `IDENTIFY_CARD`, then `{attestation_tlv, nullifier, verified}`.
  - `card_status()` — reader and card presence.
- **`crates/keycard-attest`** (attestation verify) and **`crates/keycard-client`**
  (PC/SC transport) — the shared keycard crates, a Cargo workspace both modules
  consume as a git dependency (tag `keycard-crates-v0.1.0`). `rln_gifter_module`
  uses only `keycard-attest`, so it carries no PC/SC dependency.

Both modules drive `libp2p_module` through its generic custom-protocol bridge
(`protocolRequest`, `protocolAcceptStream`, `streamReadLpJson`,
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
  |    EIP-191 sig or keycard attestation    |-- 2. register_member on
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

A gifter accepts either scheme, or both, per its `serve` configuration:

- **Eth allowlist (EIP-191).** The client `personal_sign`s the lowercase hex of
  the 32-byte identity commitment. The gifter recovers the 20-byte address and
  checks it against a lowercase `0x`-hex allowlist. Each address gets one
  membership; a consumed set rejects repeats.
- **Keycard attestation.** The client sends the raw `IDENTIFY_CARD` TLV, signed
  over the commitment-bound challenge
  `SHA256("logos/rln/keycard-attest/1" || id_commitment)`. The gifter recovers
  the vendor CA from the card certificate, checks it against a trusted-CA set,
  verifies the challenge signature, and derives the once-per-card nullifier
  `keccak256(ident_pub)` — stable across factory resets, so each card claims
  exactly one membership. The consumed-nullifier set is optionally persisted to
  an append-only file across restarts.

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
| `rust/rln-gifter-module/` | gifter module — `request` (client) + `serve` (server), wire codec, cross-module `lp_*` client |
| `rust/keycard-capture-module/` | client-side PC/SC keycard capture module |
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
