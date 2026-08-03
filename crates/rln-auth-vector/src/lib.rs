//! Contract kit for RLN gifter auth vectors.
//!
//! An auth vector is a strategy for authorizing a gifted membership
//! allocation. It has two roles, each shipped as a method on a logos module:
//!
//! - **producer** (client side, next to the requester): given the identity
//!   commitment, produce the `authentication_payload` bytes —
//!   [`PRODUCE_METHOD`] (`produce_auth`).
//! - **verifier** (server side, next to the gifter): given the payload and
//!   commitment, decide the request — [`VERIFY_METHOD`] (`verify_auth`).
//!
//! Both methods take ONE JSON-string argument and return a JSON string; the
//! serde types in this crate ARE the normative shapes. `rln_gifter_module`
//! serializes the requests and parses the replies with these same types, so a
//! vector module built against this crate is wire-compatible by construction.
//! A module in another language conforms by speaking the same JSON — this
//! crate is the Rust convenience, not a requirement.
//!
//! A vector implements [`AuthVector`] (either role or both; the defaults
//! answer "unsupported") and wires its module methods through
//! [`dispatch_produce`] / [`dispatch_verify`], which do the parse / route /
//! serialize / error-envelope steps uniformly. One module may host several
//! vectors — every request names its `auth_type`, and dispatch routes over
//! the slice you pass.
//!
//! Success and refusal both travel as data (`{"payload_hex"}` /
//! [`Verdict`]); the `{"error": "..."}` envelope is reserved for malformed
//! requests and internal failures.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Canonical producer method name every vector module exposes.
pub const PRODUCE_METHOD: &str = "produce_auth";
/// Canonical verifier method name every vector module exposes.
pub const VERIFY_METHOD: &str = "verify_auth";

/// Well-known `authentication_type` strings of the reference vectors. The
/// vocabulary is open — these are just the names the reference modules
/// registered; a new vector picks its own string and needs no entry here.
pub const KEYCARD_ATTEST_AUTH_TYPE: &str = "keycard-attestation";
pub const ETH_ALLOWLIST_AUTH_TYPE: &str = "eth-allowlist";

/// `produce_auth` input: make the `authentication_payload` for this
/// commitment. `args` is the caller's opaque extra material (a voucher code,
/// a derivation hint …), forwarded verbatim from the requesting application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProduceRequest {
    pub auth_type: String,
    pub id_commitment_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Value>,
}

/// `produce_auth` output: the payload bytes, hex-encoded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProduceReply {
    pub payload_hex: String,
}

/// `verify_auth` input. `config` is the gifter operator's opaque per-vector
/// configuration (trusted CAs, an allowlist …), passed through verbatim from
/// the gifter's `authVerifiers` entry on every call — verifiers stay
/// stateless.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub auth_type: String,
    pub payload_hex: String,
    pub id_commitment_hex: String,
    #[serde(default)]
    pub rate: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<Value>,
}

/// `verify_auth` output. A refusal is `ok: false` + `reason` — still a
/// successful verify call. Returning a `nullifier` (any stable lowercase
/// string identifying the spent credential) opts in to the gifter's shared
/// replay protection: reserved before the on-chain register, rolled back on
/// its failure, persisted on success.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nullifier: Option<String>,
}

impl Verdict {
    pub fn accept(nullifier: Option<String>) -> Self {
        Verdict { ok: true, reason: None, nullifier }
    }
    pub fn reject(reason: impl Into<String>) -> Self {
        Verdict { ok: false, reason: Some(reason.into()), nullifier: None }
    }
}

/// One auth vector. Implement the role(s) your module ships; the defaults
/// answer "unsupported on this side" through the standard error envelope, so
/// a verify-only vector needs no produce stub and vice versa.
pub trait AuthVector {
    /// The `authentication_type` string this vector owns.
    fn auth_type(&self) -> &'static str;

    fn produce(&self, req: &ProduceRequest) -> Result<ProduceReply, String> {
        let _ = req;
        Err(format!("auth vector '{}' has no producer on this module", self.auth_type()))
    }

    fn verify(&self, req: &VerifyRequest) -> Result<Verdict, String> {
        let _ = req;
        Err(format!("auth vector '{}' has no verifier on this module", self.auth_type()))
    }
}

fn error_reply(msg: &str) -> String {
    serde_json::json!({ "error": msg }).to_string()
}

fn route<'a>(
    vectors: &'a [&'a dyn AuthVector],
    auth_type: &str,
) -> Result<&'a dyn AuthVector, String> {
    vectors
        .iter()
        .find(|v| v.auth_type() == auth_type)
        .copied()
        .ok_or_else(|| format!("unknown auth_type '{auth_type}' on this module"))
}

/// Module-method glue for [`PRODUCE_METHOD`]: `args_json` in, reply JSON out.
pub fn dispatch_produce(args_json: &str, vectors: &[&dyn AuthVector]) -> String {
    let run = || -> Result<ProduceReply, String> {
        let req: ProduceRequest =
            serde_json::from_str(args_json).map_err(|e| format!("produce_auth args: {e}"))?;
        route(vectors, &req.auth_type)?.produce(&req)
    };
    match run() {
        Ok(reply) => serde_json::to_string(&reply).unwrap_or_else(|e| error_reply(&e.to_string())),
        Err(e) => error_reply(&e),
    }
}

/// Module-method glue for [`VERIFY_METHOD`]: `args_json` in, reply JSON out.
pub fn dispatch_verify(args_json: &str, vectors: &[&dyn AuthVector]) -> String {
    let run = || -> Result<Verdict, String> {
        let req: VerifyRequest =
            serde_json::from_str(args_json).map_err(|e| format!("verify_auth args: {e}"))?;
        route(vectors, &req.auth_type)?.verify(&req)
    };
    match run() {
        Ok(verdict) => {
            serde_json::to_string(&verdict).unwrap_or_else(|e| error_reply(&e.to_string()))
        }
        Err(e) => error_reply(&e),
    }
}

/// Parse a producer module's reply (the caller side of [`PRODUCE_METHOD`]),
/// surfacing the `{"error"}` envelope as `Err`.
pub fn parse_produce_reply(reply: &Value) -> Result<ProduceReply, String> {
    if let Some(e) = reply.get("error").and_then(Value::as_str) {
        return Err(e.to_string());
    }
    serde_json::from_value(reply.clone()).map_err(|e| format!("produce_auth reply: {e}"))
}

/// Parse a verifier module's reply (the caller side of [`VERIFY_METHOD`]),
/// surfacing the `{"error"}` envelope as `Err`.
pub fn parse_verdict(reply: &Value) -> Result<Verdict, String> {
    if let Some(e) = reply.get("error").and_then(Value::as_str) {
        return Err(e.to_string());
    }
    serde_json::from_value(reply.clone()).map_err(|e| format!("verify_auth reply: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct VerifyOnly;
    impl AuthVector for VerifyOnly {
        fn auth_type(&self) -> &'static str {
            "verify-only"
        }
        fn verify(&self, req: &VerifyRequest) -> Result<Verdict, String> {
            if req.payload_hex == "00" {
                Ok(Verdict::reject("zero payload"))
            } else {
                Ok(Verdict::accept(Some(format!("nul-{}", req.id_commitment_hex))))
            }
        }
    }

    struct ProduceOnly;
    impl AuthVector for ProduceOnly {
        fn auth_type(&self) -> &'static str {
            "produce-only"
        }
        fn produce(&self, req: &ProduceRequest) -> Result<ProduceReply, String> {
            Ok(ProduceReply { payload_hex: format!("aa{}", req.id_commitment_hex) })
        }
    }

    fn vectors() -> Vec<Box<dyn AuthVector>> {
        vec![Box::new(VerifyOnly), Box::new(ProduceOnly)]
    }

    #[test]
    fn dispatch_routes_by_auth_type_across_a_multi_vector_module() {
        let vs = vectors();
        let refs: Vec<&dyn AuthVector> = vs.iter().map(|b| b.as_ref()).collect();

        let req = serde_json::json!({
            "auth_type": "produce-only", "id_commitment_hex": "beef"
        });
        let out: Value =
            serde_json::from_str(&dispatch_produce(&req.to_string(), &refs)).unwrap();
        assert_eq!(out["payload_hex"], "aabeef");

        let req = serde_json::json!({
            "auth_type": "verify-only", "payload_hex": "01", "id_commitment_hex": "beef"
        });
        let out: Value = serde_json::from_str(&dispatch_verify(&req.to_string(), &refs)).unwrap();
        assert_eq!(out["ok"], true);
        assert_eq!(out["nullifier"], "nul-beef");
    }

    #[test]
    fn refusal_is_a_verdict_not_an_error() {
        let vs = vectors();
        let refs: Vec<&dyn AuthVector> = vs.iter().map(|b| b.as_ref()).collect();
        let req = serde_json::json!({
            "auth_type": "verify-only", "payload_hex": "00", "id_commitment_hex": "beef"
        });
        let out: Value = serde_json::from_str(&dispatch_verify(&req.to_string(), &refs)).unwrap();
        assert_eq!(out["ok"], false);
        assert_eq!(out["reason"], "zero payload");
        assert!(out.get("error").is_none());
    }

    #[test]
    fn unsupported_side_and_unknown_type_use_the_error_envelope() {
        let vs = vectors();
        let refs: Vec<&dyn AuthVector> = vs.iter().map(|b| b.as_ref()).collect();

        let req = serde_json::json!({
            "auth_type": "verify-only", "id_commitment_hex": "beef"
        });
        let out: Value =
            serde_json::from_str(&dispatch_produce(&req.to_string(), &refs)).unwrap();
        assert!(out["error"].as_str().unwrap().contains("no producer"), "got: {out}");

        let req = serde_json::json!({
            "auth_type": "nope", "payload_hex": "01", "id_commitment_hex": "beef"
        });
        let out: Value = serde_json::from_str(&dispatch_verify(&req.to_string(), &refs)).unwrap();
        assert!(out["error"].as_str().unwrap().contains("unknown auth_type"), "got: {out}");
    }

    #[test]
    fn reply_parsers_surface_the_error_envelope() {
        let ok = serde_json::json!({ "payload_hex": "aa" });
        assert_eq!(parse_produce_reply(&ok).unwrap().payload_hex, "aa");
        let err = serde_json::json!({ "error": "boom" });
        assert_eq!(parse_produce_reply(&err).unwrap_err(), "boom");

        let verdict = serde_json::json!({ "ok": true, "nullifier": "n" });
        assert_eq!(parse_verdict(&verdict).unwrap().nullifier.as_deref(), Some("n"));
        assert_eq!(parse_verdict(&err).unwrap_err(), "boom");
    }

    #[test]
    fn request_shapes_round_trip_with_optional_fields_omitted() {
        let req = VerifyRequest {
            auth_type: "t".into(),
            payload_hex: "aa".into(),
            id_commitment_hex: "bb".into(),
            rate: 0,
            config: None,
        };
        let v = serde_json::to_value(&req).unwrap();
        assert!(v.get("config").is_none(), "unset config must be omitted");
        let back: VerifyRequest = serde_json::from_value(v).unwrap();
        assert_eq!(back.auth_type, "t");

        // Older callers omitting `rate` still parse (serde default).
        let min = serde_json::json!({
            "auth_type": "t", "payload_hex": "aa", "id_commitment_hex": "bb"
        });
        let back: VerifyRequest = serde_json::from_value(min).unwrap();
        assert_eq!(back.rate, 0);
    }
}
