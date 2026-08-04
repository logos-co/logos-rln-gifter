// Keycard attestation VERIFIER for gifted RLN registration — the server-side
// half of the keycard auth vector (the producer half is keycard-capture-module,
// kept separate so a headless gifter node never links PC/SC).
// FEATURE: RLN gifter keycard auth vector (verify)

use rln_auth_vector::{dispatch_verify, AuthVector, Verdict, VerifyRequest};

use keycard_attest::attest::{bound_challenge, parse_attestation, verify_attestation};

pub trait KeycardAuthModule: Send + 'static {
    /// rln_auth_vector VERIFY_METHOD for auth_type "keycard-attestation".
    /// One JSON-string arg (VerifyRequest); config: `{"trusted_cas":
    /// ["<33-byte compressed CA pubkey hex>", …]}`. Accepts with the
    /// once-per-card nullifier, so the gifter's shared replay protection
    /// applies. `{"ok", "reason"?, "nullifier"?}` or `{"error"}`.
    fn verify_auth(&mut self, args_json: String) -> String;
    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {}
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

#[derive(Default)]
struct KeycardAuth {}

struct KeycardVector;

impl AuthVector for KeycardVector {
    fn auth_type(&self) -> &'static str {
        rln_auth_vector::KEYCARD_ATTEST_AUTH_TYPE
    }

    // Malformed config is an Err (operator mistake, error envelope); a payload
    // that doesn't verify is a REJECT verdict (untrusted input, normal flow).
    fn verify(&self, req: &VerifyRequest) -> Result<Verdict, String> {
        let trusted_cas = parse_trusted_cas(req.config.as_ref())?;
        if trusted_cas.is_empty() {
            return Err("config.trusted_cas is empty — nothing can verify".into());
        }
        let payload = match hex::decode(req.payload_hex.trim_start_matches("0x")) {
            Ok(p) => p,
            Err(e) => return Ok(Verdict::reject(format!("payload hex: {e}"))),
        };
        let id_commitment = match hex::decode(req.id_commitment_hex.trim_start_matches("0x")) {
            Ok(c) => c,
            Err(e) => return Ok(Verdict::reject(format!("id_commitment hex: {e}"))),
        };

        let att = match parse_attestation(&payload) {
            Ok(a) => a,
            Err(e) => return Ok(Verdict::reject(format!("attestation parse failed: {e}"))),
        };
        let challenge = bound_challenge(&id_commitment);
        match verify_attestation(&att, &trusted_cas, &challenge) {
            Ok(nullifier) => Ok(Verdict::accept(Some(hex::encode(nullifier)))),
            Err(e) => Ok(Verdict::reject(format!("attestation verification failed: {e}"))),
        }
    }
}

fn parse_trusted_cas(config: Option<&serde_json::Value>) -> Result<Vec<[u8; 33]>, String> {
    let arr = config
        .and_then(|c| c.get("trusted_cas"))
        .and_then(|v| v.as_array())
        .ok_or("config.trusted_cas (array of 33-byte CA pubkey hex) is required")?;
    let mut cas = Vec::with_capacity(arr.len());
    for e in arr {
        let s = e.as_str().ok_or("trusted_cas entries must be hex strings")?;
        let bytes =
            hex::decode(s.trim_start_matches("0x")).map_err(|e| format!("trusted_cas hex: {e}"))?;
        let ca: [u8; 33] =
            bytes.as_slice().try_into().map_err(|_| "trusted_cas entries must be 33 bytes")?;
        cas.push(ca);
    }
    Ok(cas)
}

impl KeycardAuthModule for KeycardAuth {
    // Plain String (not Result): codegen maps Result to LogosResult, which the
    // host nulls through the UI bridge; errors travel as {"error":...}.
    fn verify_auth(&mut self, args_json: String) -> String {
        dispatch_verify(&args_json, &[&KeycardVector])
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<KeycardAuth>();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(config: Option<serde_json::Value>, payload_hex: &str) -> VerifyRequest {
        VerifyRequest {
            auth_type: rln_auth_vector::KEYCARD_ATTEST_AUTH_TYPE.into(),
            payload_hex: payload_hex.into(),
            id_commitment_hex: "11".repeat(32),
            rate: 100,
            config,
        }
    }

    #[test]
    fn missing_bad_or_empty_trusted_cas_is_an_operator_error() {
        assert!(KeycardVector.verify(&req(None, "aa")).unwrap_err().contains("required"));
        let bad_hex = serde_json::json!({ "trusted_cas": ["zz"] });
        assert!(KeycardVector.verify(&req(Some(bad_hex), "aa")).unwrap_err().contains("hex"));
        let bad_len = serde_json::json!({ "trusted_cas": ["aa"] });
        assert!(KeycardVector.verify(&req(Some(bad_len), "aa")).unwrap_err().contains("33 bytes"));
        let empty = serde_json::json!({ "trusted_cas": [] });
        assert!(KeycardVector.verify(&req(Some(empty), "aa")).unwrap_err().contains("empty"));
    }

    #[test]
    fn undecodable_or_unparseable_payload_is_rejected_not_errored() {
        let cfg = serde_json::json!({ "trusted_cas": ["02".to_owned() + &"ab".repeat(32)] });
        let v = KeycardVector.verify(&req(Some(cfg.clone()), "zz")).unwrap();
        assert!(!v.ok);
        assert!(v.reason.unwrap().contains("payload hex"));
        let v = KeycardVector.verify(&req(Some(cfg), &"00".repeat(8))).unwrap();
        assert!(!v.ok);
        assert!(v.reason.unwrap().contains("parse failed"));
    }
}
