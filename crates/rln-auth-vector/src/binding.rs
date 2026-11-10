//! What gets signed: the identity commitment, the highest rate the payload
//! may be used for, the gifter it is meant for, and the authoriser's evidence.

use std::borrow::Cow;

use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};

use crate::authtype::AuthType;
use crate::hex::{hex32_bytes, strip_0x};
use crate::pieces::Outcome;
use crate::reason;
use crate::types::{ProduceRequest, VerifyRequest};

/// `rate_max` when the producer's args name none — the gifter's default rate.
pub const DEFAULT_RATE_MAX: u64 = 100;
/// Longest accepted `audience`, in bytes.
pub const MAX_AUDIENCE_LEN: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub id_commitment: [u8; 32],
    pub rate_max: u64,
    pub audience: String,
}

/// `args` as an object: `None`, `null` and `""` are no args; a string holding
/// a JSON object (the membership module may stringify `auth_args`) is
/// unwrapped; anything else that is not an object is an error.
pub fn args_object(raw: Option<&Value>) -> Result<Option<Map<String, Value>>, String> {
    Ok(args_object_cow(raw)?.map(Cow::into_owned))
}

/// [`args_object`] for readers: an object `raw` is borrowed, a stringified
/// one is parsed into an owned map.
pub fn args_object_cow(raw: Option<&Value>) -> Result<Option<Cow<'_, Map<String, Value>>>, String> {
    match raw {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
        Some(Value::String(s)) => {
            let inner: Value = serde_json::from_str(s)
                .map_err(|e| format!("args: string is not valid JSON: {e}"))?;
            match inner {
                Value::Null => Ok(None),
                Value::Object(o) => Ok(Some(Cow::Owned(o))),
                other => Err(format!("args: expected JSON object, got {other}")),
            }
        }
        Some(Value::Object(o)) => Ok(Some(Cow::Borrowed(o))),
        Some(v) => Err(format!("args: expected JSON object, got {v}")),
    }
}

/// A string of at most [`MAX_AUDIENCE_LEN`] bytes; absent or `null` is "".
pub fn parse_audience(v: Option<&Value>, field: &str) -> Result<String, String> {
    match v {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(s)) if s.len() <= MAX_AUDIENCE_LEN => Ok(s.clone()),
        Some(Value::String(s)) => Err(format!(
            "{field}: at most {MAX_AUDIENCE_LEN} bytes, got {}",
            s.len()
        )),
        Some(v) => Err(format!("{field}: expected string, got {v}")),
    }
}

/// An unsigned integer, given as a number or a numeric string; absent or
/// `null` is [`DEFAULT_RATE_MAX`].
pub fn parse_rate_max(v: Option<&Value>, field: &str) -> Result<u64, String> {
    match v {
        None | Some(Value::Null) => Ok(DEFAULT_RATE_MAX),
        Some(Value::Number(n)) => n
            .as_u64()
            .ok_or_else(|| format!("{field}: expected unsigned integer, got {n}")),
        Some(Value::String(s)) => s
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("{field}: expected unsigned integer, got {s:?}")),
        Some(v) => Err(format!("{field}: expected unsigned integer, got {v}")),
    }
}

impl Binding {
    /// The producer side: the commitment from the request, `rate_max` and
    /// `audience` from `args` (defaults 100 and ""). Problems are the
    /// caller's and surface as errors.
    pub fn from_produce(req: &ProduceRequest) -> Result<Binding, String> {
        let id_commitment = hex32_bytes("id_commitment_hex", &req.id_commitment_hex)?;
        let args = args_object_cow(req.args.as_ref())?;
        let get = |k: &str| args.as_ref().and_then(|o| o.get(k));
        Ok(Binding {
            id_commitment,
            rate_max: parse_rate_max(get("rate_max"), "rate_max")?,
            audience: parse_audience(get("audience"), "audience")?,
        })
    }

    /// The verifier side: the commitment from the request, `rate_max` as the
    /// payload carried it, `audience` as the operator configured it. A
    /// malformed commitment is the requester's problem: a reject.
    pub fn for_verify(req: &VerifyRequest, rate_max: u64, audience: &str) -> Outcome<Binding> {
        let raw = match hex::decode(strip_0x(&req.id_commitment_hex)) {
            Ok(c) => c,
            Err(e) => return Outcome::Reject(reason::idc_hex(e)),
        };
        let id_commitment: [u8; 32] = match raw.try_into() {
            Ok(c) => c,
            Err(v) => return Outcome::Reject(reason::idc_len(v.len())),
        };
        Outcome::Ok(Binding {
            id_commitment,
            rate_max,
            audience: audience.to_string(),
        })
    }
}

/// The 32 bytes a scheme signs:
/// `sha256(domain ‖ id_commitment ‖ rate_max u64 LE ‖ u8 len(audience) ‖ audience ‖ extra)`,
/// `domain` = [`AuthType::domain`], `extra` = the authoriser's bound evidence
/// (empty for most). The length byte keeps `audience ‖ extra` unambiguous.
pub fn binding_digest(t: &AuthType, b: &Binding, extra: &[u8]) -> [u8; 32] {
    let a = b.audience.as_bytes();
    let len = u8::try_from(a.len())
        .expect("invariant: audience is at most MAX_AUDIENCE_LEN bytes (parse_audience)");
    let mut h = Sha256::new();
    h.update(t.domain());
    h.update(b.id_commitment);
    h.update(b.rate_max.to_le_bytes());
    h.update([len]);
    h.update(a);
    h.update(extra);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn produce(args: Option<Value>) -> ProduceRequest {
        ProduceRequest {
            auth_type: "t-a".into(),
            id_commitment_hex: "01".repeat(32),
            args,
        }
    }

    #[test]
    fn args_object_unwraps_strings() {
        assert_eq!(args_object(None).unwrap(), None);
        assert_eq!(args_object(Some(&json!(null))).unwrap(), None);
        assert_eq!(args_object(Some(&json!(" "))).unwrap(), None);
        assert_eq!(args_object(Some(&json!("null"))).unwrap(), None);
        let o = args_object(Some(&json!("{\"private_key\":\"0x01\"}")))
            .unwrap()
            .unwrap();
        assert_eq!(o["private_key"], "0x01");
        assert!(args_object(Some(&json!("[1]")))
            .unwrap_err()
            .contains("expected JSON object"));
        assert!(args_object(Some(&json!("{")))
            .unwrap_err()
            .contains("not valid JSON"));
        assert!(args_object(Some(&json!(7)))
            .unwrap_err()
            .contains("expected JSON object"));
    }

    #[test]
    fn produce_binding_defaults_and_overrides() {
        let b = Binding::from_produce(&produce(None)).unwrap();
        assert_eq!(
            (b.id_commitment, b.rate_max, b.audience.as_str()),
            ([1u8; 32], 100, "")
        );
        let b = Binding::from_produce(&produce(Some(json!({ "rate_max": 7, "audience": "poc" }))))
            .unwrap();
        assert_eq!((b.rate_max, b.audience.as_str()), (7, "poc"));
        let b = Binding::from_produce(&produce(Some(json!("{\"rate_max\": \"9\"}")))).unwrap();
        assert_eq!(b.rate_max, 9, "a numeric string counts");
        for bad in [
            json!({ "rate_max": -1 }),
            json!({ "rate_max": "x" }),
            json!({ "rate_max": true }),
        ] {
            assert!(Binding::from_produce(&produce(Some(bad)))
                .unwrap_err()
                .starts_with("rate_max"));
        }
        assert!(
            Binding::from_produce(&produce(Some(json!({ "audience": 1 }))))
                .unwrap_err()
                .starts_with("audience")
        );
        assert!(
            Binding::from_produce(&produce(Some(json!({ "audience": "x".repeat(256) })))).is_err()
        );
        assert!(
            Binding::from_produce(&produce(Some(json!({ "audience": "x".repeat(255) })))).is_ok()
        );
        let mut short = produce(None);
        short.id_commitment_hex = "01".repeat(31);
        assert!(Binding::from_produce(&short)
            .unwrap_err()
            .starts_with("id_commitment_hex"));
    }

    #[test]
    fn verify_binding_rejects_a_bad_commitment() {
        let mut req = VerifyRequest {
            auth_type: "t-a".into(),
            payload_hex: String::new(),
            id_commitment_hex: format!("0X{}", "ab".repeat(32)),
            rate: 1,
            config: None,
            peer_id: None,
        };
        let Outcome::Ok(b) = Binding::for_verify(&req, 5, "aud") else {
            panic!()
        };
        assert_eq!(
            (b.id_commitment, b.rate_max, b.audience.as_str()),
            ([0xab; 32], 5, "aud")
        );
        req.id_commitment_hex = "ab".repeat(31);
        let Outcome::Reject(r) = Binding::for_verify(&req, 5, "") else {
            panic!()
        };
        assert_eq!(r, "id_commitment must be 32 bytes, got 31");
        req.id_commitment_hex = "zz".repeat(32);
        assert!(
            matches!(Binding::for_verify(&req, 5, ""), Outcome::Reject(r) if r.starts_with("id_commitment hex:"))
        );
    }

    #[test]
    fn digest_known_answer() {
        // idc 0x01..0x20, rate_max 100, audience "", no extra, type lez-allowlist.
        let idc: [u8; 32] = core::array::from_fn(|i| i as u8 + 1);
        let b = Binding {
            id_commitment: idc,
            rate_max: 100,
            audience: String::new(),
        };
        let d = binding_digest(&AuthType::new("lez", "allowlist"), &b, &[]);
        let mut h = Sha256::new();
        h.update(b"logos/rln/lez-allowlist/2");
        h.update(idc);
        h.update(100u64.to_le_bytes());
        h.update([0u8]);
        let by_hand: [u8; 32] = h.finalize().into();
        assert_eq!(d, by_hand);
        assert_eq!(
            hex::encode(d),
            "cefb1945e8502986bb4fc29a949124fb9ee7983f3d10f0fbb7895ec36db87ac1"
        );
        // Every field moves the digest.
        let b2 = Binding {
            audience: "x".into(),
            ..b
        };
        assert_ne!(
            binding_digest(&AuthType::new("lez", "allowlist"), &b2, &[]),
            d
        );
        assert_ne!(
            binding_digest(&AuthType::new("lez", "allowlist"), &b, &[1]),
            d
        );
        assert_ne!(
            binding_digest(&AuthType::new("logos", "allowlist"), &b, &[]),
            d
        );
    }
}
