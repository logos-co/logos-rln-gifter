# rln_auth_vector

Contract kit for RLN gifter **auth vectors** — the pluggable strategies that
authorize a gifted membership allocation. Import this crate to build a vector
module that both `rln_gifter_module` (client and server) and any application
can use with configuration only. The normative description of the contract,
the composition rule, the binding digest, the payload frame and the reasons
is [`docs/auth-vectors.md`](../../docs/auth-vectors.md); this crate is its
Rust form.

## What is here

- `types`: the two methods' JSON shapes (`ProduceRequest` / `ProduceReply`,
  `VerifyRequest` / `Verdict`), the caller-side parsers, and
  `namespaced_nullifier` (the gifter's `<registry>:<auth_type>:<nullifier>`).
- `AuthType`: `<scheme>-<authoriser>`, split at the first dash; its digest
  domain `logos/rln/<name>/2`.
- `Binding` + `binding_digest`: what gets signed; `frame` / `unframe`: the
  payload `0x02 ‖ scheme part ‖ evidence ‖ rate_max LE`.
- `pieces`: the `Scheme` / `Authoriser` (verify side) and `Signer` /
  `Claimant` (produce side) traits, `Identity`, and `Outcome` (a reject) vs
  `Err` (an operator mistake).
- `registry`: `VerifyRegistry` / `ProduceRegistry` compose the pieces a module
  ships and answer every composition that exists; `dispatch_verify` /
  `dispatch_produce` are the module-method glue.
- `flow`: `verify_flow` and `produce_flow`, the one pipeline.
- `reason`: the reject strings, written once.

## Building a module

```rust
use rln_auth_vector::{dispatch_verify, VerifyRegistry};
use rln_auth_vectors::authoriser::Allowlist;
use rln_auth_vectors::scheme::{Eth, Lez};

fn registry() -> VerifyRegistry {
    VerifyRegistry::new().scheme(Eth).scheme(Lez).authoriser(Allowlist)
    // answers "eth-allowlist" and "lez-allowlist"
}

fn verify_auth(&mut self, args_json: String) -> String {
    dispatch_verify(&args_json, &registry())
}
```

A new scheme implements `Scheme` (and `Signer` for its produce half); a new
authoriser implements `Authoriser` (and `Claimant`); neither needs a name
registered anywhere — the composition is the name. `crates/rln-auth-vectors`
holds the reference pieces.

## Wiring it up (configuration only)

- **Gifter node** — `rln_gifter_module.serve` args:
  `"authVerifiers": {"eth-allowlist": {"module": "rln_auth_module", "config": {…}}}`.
- **Requester** — `rln_gifter_module.request` args: `"authType"` plus
  `"authPayload"` (raw framed hex) or `"authProvider": "rln_sign_module"`;
  through the RLN membership module, the same as the RegistryOptions
  `auth_type` / `auth_payload` / `auth_provider` / `auth_args`.
- The host application declares its chosen vector modules in its
  `metadata.json` dependencies so they get installed and loaded.
