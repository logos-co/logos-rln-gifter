# rln_auth_vector

Contract kit for RLN gifter **auth vectors** — the pluggable strategies that
authorize a gifted membership allocation. Import this crate to build a vector
module that both `rln_gifter_module` (client and server) and any application
can use with configuration only.

## The contract

A vector is a logos module exposing one or both of two canonical methods,
each taking ONE JSON-string argument and returning a JSON string:

| Method | Role | In | Out |
|---|---|---|---|
| `produce_auth` | client side — make the `authentication_payload` | `{"auth_type", "id_commitment_hex", "args"?}` | `{"payload_hex"}` |
| `verify_auth` | gifter side — decide the request | `{"auth_type", "payload_hex", "id_commitment_hex", "rate", "config"?}` | `{"ok", "reason"?, "nullifier"?}` |

- `args` is the requesting application's opaque extra material, forwarded
  verbatim.
- `config` is the gifter operator's opaque per-vector configuration from the
  `authVerifiers` serve entry, passed on every call — verifiers stay
  stateless.
- A refusal is `{"ok": false, "reason": …}` — still a successful call. The
  `{"error": "…"}` envelope is reserved for malformed requests and internal
  failures.
- A returned `nullifier` (any stable lowercase string naming the spent
  credential) opts in to the gifter's shared replay protection:
  reserve-before-register, rollback on failure, persist on success.

The serde types in `src/lib.rs` are the normative shapes. A module in another
language conforms by speaking the same JSON.

## Building a vector in Rust

```rust
use rln_auth_vector::{AuthVector, VerifyRequest, Verdict, dispatch_verify};

struct Voucher;
impl AuthVector for Voucher {
    fn auth_type(&self) -> &'static str { "voucher-v1" }
    fn verify(&self, req: &VerifyRequest) -> Result<Verdict, String> {
        // check req.payload_hex against req.config…
        Ok(Verdict::accept(Some("voucher:1234".into())))
    }
}

// The module method is one line of glue:
fn verify_auth(&mut self, args_json: String) -> String {
    dispatch_verify(&args_json, &[&Voucher])
}
```

Implement `produce` too (or instead) for the client side; the trait defaults
answer "unsupported on this side". One module may host several vectors —
dispatch routes by `auth_type` over the slice you pass.

## Wiring it up (configuration only)

- **Gifter node** — `rln_gifter_module.serve` args:
  `"authVerifiers": {"voucher-v1": {"module": "voucher_module", "config": {…}}}`.
- **Requester** — `rln_gifter_module.request` args: `"authType":
  "voucher-v1"` plus `"authPayload"` (raw hex) or `"authProvider":
  "voucher_module"`; through the RLN membership module, the same as the flat
  RegistryOptions `auth_type` / `auth_payload` / `auth_provider` /
  `auth_args`.
- The host application declares its chosen vector modules in its
  `metadata.json` dependencies so they get installed and loaded.

Reference vectors in this repo: `rust/keycard-auth-module` (verifier),
`rust/keycard-capture-module` (producer), `rust/eth-auth-module` (verifier).
