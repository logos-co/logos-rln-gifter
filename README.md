# logos-rln-gifter

Standalone [nim-libp2p](https://github.com/vacp2p/nim-libp2p) protocol for
**gifted RLN membership allocation** (LIP-158): a funded *gifter* node
registers RLN memberships on-chain **on behalf of** authenticated clients, so
clients never hold funds or sign their own registration — and their RLN
identity secret never leaves their machine.

Ported from the nwaku `rln_gifter`, with waku dependencies replaced by plain
nim-libp2p. This repo is transport + authentication only: the actual on-chain
registration is delegated to a host-provided handler, and RLN proof
generation/verification (LIP-144) lives elsewhere (see
[mix-rln-spam-protection-plugin](https://github.com/adklempner/mix-rln-spam-protection-plugin)).

## How it works

```
client                                  gifter (funded wallet)
  |                                        |
  |  /logos/rln/membership/1.0.0           |
  |  RlnGifterRequest {                    |
  |    identityCommitment,                 |-- 1. recover eth address from the
  |    eth-allowlist auth payload  ------> |     EIP-191 signature over the
  |    (EIP-191 sig over idCommitment)     |     identity commitment
  |  }                                     |-- 2. check allowlist, mark address
  |                                        |     consumed (one membership each)
  |                                        |-- 3. RegisterMemberHandler:
  |                                        |     host registers the commitment
  |                                        |     on-chain, funds + signs the tx
  |  RlnGifterResponse {                   |
  |    leafIndex, merkleRoot,       <----- |
  |    blockNumber, transactionHash }      |
  |                                        |
  '-- adopts the leaf: its own idSecretHash + the gifted leafIndex
```

- **Authentication** (`src/rln_gifter/eip191.nim`): EIP-191 `personal_sign`
  over the lowercase hex of the 32-byte identity commitment (human-readable in
  wallets that surface it). 65-byte recoverable secp256k1 signature; the
  recovered 20-byte address is checked against a lowercase `0x`-hex allowlist.
  Byte-compatible with the original nwaku implementation. Used **only** for
  client↔gifter auth — RLN proofs are untouched.
- **One-shot allowlist** (`EthAllowlistAuth`): each address gets exactly one
  membership; a consumed set rejects repeats.
- **Keycard attestation** (`src/rln_gifter/keycard_attest.nim`, pluggable
  alongside the allowlist): a client proves it holds a genuine
  [Keycard](https://keycard.tech) by sending the raw `IDENTIFY_CARD` TLV signed
  over the commitment-bound challenge
  `SHA256("logos/rln/keycard-attest/1" || id_commitment)`. The gifter recovers
  the vendor CA from the card certificate, checks it against a trusted-CA set,
  verifies the challenge signature, and derives the once-per-card nullifier
  `keccak256(ident_pub)` — stable across factory resets, so each card claims
  exactly one membership (`KeycardAttestAuth`, optionally persisted to an
  append-only file across restarts).
- **Delegated registration** (`RegisterMemberHandler`): the protocol never
  touches a chain. The host receives `(identityCommitment, rateLimit)` and
  returns the allocation (`leafIndex`, `merkleRoot`, `blockNumber`,
  `transactionHash`) or an error, which is relayed verbatim to the client.

## Layout

| Path | What |
|---|---|
| `src/rln_gifter/protocol.nim` | `RlnGifter` LPProtocol (server): auth + delegate + respond |
| `src/rln_gifter/client.nim` | `requestMembership`: dial, sign, request, decode |
| `src/rln_gifter/rpc.nim`, `rpc_codec.nim` | request/response types + protobuf codec (`/logos/rln/membership/1.0.0`) |
| `src/rln_gifter/eip191.nim` | EIP-191 sign / recover primitives |
| `src/rln_gifter/keycard_attest.nim` | Keycard `IDENTIFY_CARD` attestation verifier (TLV parse, CA recovery, challenge binding, nullifier) |
| `src/rln_gifter/keycard_auth.nim` | keycard auth state: trusted CAs + consumed nullifiers (optional persistence) |
| `cbind/cbind_gifter.nim`, `cbind/libp2p_gifter.h` | C surface for host applications (below) |

## C surface (`libp2p_gifter_*`)

For hosts driving libp2p through C bindings. Designed to be **superset-linked**
into the mix cbind library (mix-rln-spam-protection-plugin's `cbind-rln`
output bundles mix + RLN + gifter into one `libp2p.so`):

- `libp2p_gifter_serve(ctx, config_json, register_cb, mount_cb, ...)` — mount
  the gifter with an `allowlist` (EIP-191) and/or `trustedCAs` (keycard
  attestation). The register callback fires **on the libp2p
  thread**, where calling back into the host runtime may deadlock — it must
  only enqueue; the host does the on-chain registration on its own thread and
  finishes with…
- `libp2p_gifter_complete(handle, result_json)` — deliver the allocation
  result for a pending registration.
- `libp2p_gifter_request(ctx, args_json, ...)` — client side: obtain a gifted
  membership from a gifter peer, authenticating with `authKey` (EIP-191) or
  `attestation` (hex keycard TLV, takes precedence).

Malformed serve-config JSON fails the mount rather than mounting without auth.
Every export registers the calling host thread with the Nim GC via the mix
cbind's `initializeLibrary` (the superset library builds with `--noMain`).

## Build & test

```bash
nimble install -d
nimble test        # EIP-191 + keycard attestation vectors, codec round-trips
```

nim-libp2p is pinned to the same rev as `libp2p_mix` so a superset build
contains a single copy (see `logos_rln_gifter.nimble`).

## Working example

The [logos-rln-mix-sim](https://github.com/logos-co/logos-rln-mix-sim)
five-node simulation runs the full flow on a live testnet: relay1 mounts the
gifter and allocates memberships to four clients over this protocol, then the
mix exchange runs with per-hop RLN proofs against the gifted memberships.
