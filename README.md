# logos-rln-gifter

Gifted RLN membership allocation (LIP-158), packaged as two Logos modules. A
funded **gifter** node registers RLN memberships on-chain **on behalf of**
authenticated clients, so a client never holds funds or signs its own
registration — and its RLN identity secret never leaves its machine.

The protocol covers transport and authentication only. On-chain registration is
delegated to `liblogos_lez_rln_module`; RLN proof generation and verification
(LIP-144) live elsewhere.

## Modules

- **`rln_gifter_module`** (`rust/rln-gifter-module`) — the gifter protocol,
  client and server, vector-agnostic, exposing these methods:
  - `request(args_json)` — client side. Takes the caller's RLN identity
    commitment (supplied by the RLN membership module, which keeps the
    identity secret), obtains the auth payload for the selected vector (raw
    `authPayload` or the `authProvider` module's `produce_auth`), sends the
    request to an allocator over `libp2p_module` — the ones advertising the
    (registry, auth type) pair through libp2p service discovery first, in
    turn while none has read the request, then the configured
    `gifterPeerId`/`gifterMultiaddr` pair if any — and returns the granted
    allocation. The identity secret never reaches this module.
  - `discover(args_json)` — client side. The allocators currently
    advertising a (registry, auth type) pair, `{serviceId, candidates:
    [{peerId, addrs}], joined, peers}`; it waits up to 20 s for an outbound
    peer, and `joined:false` means none connected. A node that cannot discover
    is the error `discovery unavailable: <msg>`.
  - `serve(args_json)` — gifter side. Mounts `/logos/rln/membership/1.0.0`,
    advertises the served (registry, auth type) pairs under that id through
    libp2p service discovery (one advertisement per node, the pairs as
    digests in its data; `advertise:false` to serve unadvertised;
    `advertiseAddrs` to publish a signed record for exactly those dial
    addresses; the first advertisement waits up to 20 s for an outbound peer
    and the reply's `advertisedToPeers` is the count it was placed with),
    authenticates each request through the configured vector's `verify_auth`
    module, and registers the commitment on-chain via
    `liblogos_lez_rln_module.register_member` on a single serialized worker,
    and answers once the registry shows the membership.
- **Auth vector modules** — see [Authentication](#authentication):
  `rln-auth-module` (the gifter's verifier, every composition),
  `rln-sign-module` (the client's producer, every composition but the
  keycard) and `keycard-capture-module` (the keycard scheme's producer,
  PC/SC — separate so a headless gifter and a reader-less client never link
  `pcsclite`; also `card_status()` for UIs).
- **Crates** — `crates/rln-auth-vector` (the contract and the composition
  machinery every module above and any third-party vector imports),
  `crates/rln-auth-vectors` (the schemes and authorisers), `crates/pow-claim`,
  `crates/zksign-light`, `crates/keycard-attest` and `crates/keycard-client`,
  all consumed as git dependencies pinned by tag (`auth-crates-v*`,
  `keycard-crates-v*`).

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
  |  }                                       |      liblogos_lez_rln_module,
  |                                          |      which funds and signs the tx
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
  `config` rides along on every verify call, with the requester's transport
  peer id, so verifiers stay stateless. A verdict `nullifier` opts the spent
  credential into shared replay protection: reserved before the on-chain
  register, rolled back on its failure, persisted to the append-only
  consumed-nullifier file on success, keyed per registry (one membership
  per credential per registry). No `authVerifiers` = an open gifter.
- **Requester**: `request` takes `authType` plus either a raw `authPayload`
  (hex the application produced itself) or an `authProvider` producer module.
  No `authType` = an unauthenticated request.

An `auth_type` is a composition, `<scheme>-<authoriser>`: a **scheme** is
how the binding digest gets signed and which identity that proves (`eth`,
`lez`, `logos`, `keycard`, `peer`); an **authoriser** is how that identity
gets accepted (`allowlist`, `any`, `attestation`, `pow-claim`). Every
scheme but eth and peer signs the same binding —
`sha256("logos/rln/<auth_type>/2" ‖ commitment ‖ rate_max ‖ audience ‖
evidence)` — and every payload has the same frame (`0x02 ‖ scheme part ‖
evidence ‖ rate_max`); eth signs the EIP-191 message over the bare
commitment so any wallet can, and peer signs nothing: the libp2p stream the
request arrived on already proved the requester's peer id. The modules
compose the pieces they ship into a registry and answer every composition
that exists (`<scheme>-any` for each scheme too); the ones with a story:

| `auth_type` | proves | nullifier |
|---|---|---|
| `eth-allowlist` | an allowlisted address signed (wallet or module key) | the address |
| `lez-allowlist` | an allowlisted LEZ account key signed (BIP-340) | the account id |
| `logos-allowlist` | an allowlisted logos-blockchain node key zkSigned | K |
| `keycard-allowlist` | an allowlisted Keycard signed (IDENTIFY_CARD) | the card's identity key |
| `keycard-attestation` | a Keycard certified by a trusted CA signed | `keccak256(ident_pub)`, once per card |
| `logos-pow-claim` | a node key that owns a settled PoW reward claim signed | the claim's nullifier |
| `peer-any` | the request came over an authenticated libp2p stream — any peer, once per registry | the peer id |

Normative: [`docs/auth-vectors.md`](docs/auth-vectors.md). Per-scheme
operator and tester guidance: [`docs/auth-allowlists.md`](docs/auth-allowlists.md).

Authentication gates only the client↔gifter exchange; RLN proofs are untouched.

## Registration

The protocol never touches a chain itself. A gifter serves one or more
registries (`serve`'s `config`, plus `registries` for further ones, each
with its own `maxRateLimit`); the request names the one it wants (the
membership module sends its scope's registry), one the gifter does not
serve is refused at once, and a request naming none gets `config`. The
gifter hands `(identityCommitment, rateLimit)` to
`liblogos_lez_rln_module.register_member` on that registry, which funds the
transaction from the account `serve` names as `wallet` and signs it. That call answers when the transaction is accepted, and on LEZ
v0.3.0 the tree assigns the leaf, so the gifter then reads the membership back
(`get_membership`) and replies with the leaf the chain holds
(`leafIndex`, `transactionHash` of the submitted transaction). A registration
not on chain within 150 s is answered as a failure that says it may still
land; an authenticated credential stays spent in that case, and is released
only when nothing was submitted.

## Layout

| Path | What |
|---|---|
| `rust/rln-gifter-module/` | gifter module — `request` (client) + `serve` (server), wire codec, nullifier store, cross-module `lp_*` client; vector-agnostic |
| `rust/rln-auth-module/` | the gifter's verifier: every scheme × authoriser composition (`verify_auth`, `supported_auth_types`), no PC/SC |
| `rust/rln-sign-module/` | the client's producer: module-owned eth and lez keys, the tester's logos-blockchain node for logos and pow-claim (`produce_auth`, `identity`, `import_key`) |
| `rust/keycard-capture-module/` | the keycard scheme's producer: client-side PC/SC capture (`produce_auth`) + `card_status` |
| `crates/rln-auth-vector/` | the contract: request/reply types, `AuthType`, the binding digest and payload frame, the `Scheme`/`Authoriser`/`Signer`/`Claimant` traits, registries, flows, reasons |
| `crates/rln-auth-vectors/` | the pieces: schemes eth/lez/logos/keycard, authorisers allowlist/attestation/pow-claim, their produce halves |
| `crates/pow-claim/` | PoW reward claim discovery and chain checks |
| `crates/zksign-light/` | zkSign (Groth16) verification and the node's `/wallet/sign/zk` client |
| `crates/keycard-attest/` | keycard attestation: TLV parse, the card's challenge signature, CA recovery, nullifier |
| `crates/keycard-client/` | PC/SC keycard transport: secure channel + `IDENTIFY_CARD` |
| `tools/mint_attest.py` | mint synthetic keycard attestations for CI / e2e (not for production) |
| `Cargo.toml` | workspace over `crates/*` |

## Build

Each module is a Logos cdylib module built with Nix, producing an `.lgx`:

```bash
nix build ./rust/rln-gifter-module#lgx
nix build ./rust/keycard-capture-module#lgx
nix build ./rust/rln-auth-module#lgx   # allocator side (eth-, logos-, lez-allowlist)
nix build ./rust/rln-sign-module#lgx   # client side
```

The shared crates build as part of each module (fetched via the git dependency),
and can be checked on their own with `cargo test` from the repo root.

Developing the shared crates: `.cargo/config.toml` at the repo root patches
every git-pinned shared crate to its `crates/` path, so a `cargo test` in any
module's `rust-lib` runs against the working tree. The nix module build copies
only the module directory and never sees that patch, so a module `Cargo.lock`
written under it (path sources) must not be committed: run
`tools/dev/relock.sh` first, which restores the git sources and refuses any
lock nix could not resolve. New crate versions reach the modules through a
pushed tag and a pin bump in each module's `Cargo.toml`.

## Runtime requirements

- `rln_gifter_module` loads alongside `libp2p_module` (transport) and
  `liblogos_lez_rln_module` (on-chain registration). A gifter needs a funded
  payer; a client needs neither funds nor a wallet. A client's RLN identity
  comes from `liblogos_rln_module`, which calls the gifter for delegated
  registration.
- `keycard_capture_module` needs a PC/SC stack (`pcsclite`) and a card reader on
  the client.
