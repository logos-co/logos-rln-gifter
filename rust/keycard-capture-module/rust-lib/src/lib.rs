// Keycard IDENTIFY_CARD attestation capture for gifted RLN registration
// FEATURE: RLN membership gifter keycard capture module (client-side PC/SC)

use serde_json::json;

use keycard_attest::attest::{
    bound_challenge, parse_attestation, verify_attestation, STATUS_PRODUCTION_CA,
};
use keycard_client::{reader_card_present, Keycard};

pub trait KeycardCaptureModule: Send + 'static {
    /// Capture a Keycard attestation bound to an EXTERNALLY supplied id_commitment
    /// (the gifter path: the identity comes from a seed, the card only proves the
    /// holder owns a genuine card). IDENTIFY_CARD is a public plain-channel command
    /// — no pairing, no PIN. Returns `{attestation_tlv, nullifier, verified}` or `{error}`.
    fn capture_attestation(&mut self, id_commitment_hex: String) -> String;
    /// Is a Keycard present at the reader? `{present}` — no card session.
    fn card_status(&mut self) -> String;
    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {}
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

#[derive(Default)]
struct KeycardCapture {}

fn parse_hex32(field: &str, value: &str) -> Result<[u8; 32], String> {
    hex::decode(value.trim_start_matches("0x"))
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| format!("{field} must be 64 hex chars"))
}

impl KeycardCaptureModule for KeycardCapture {
    // Return a plain String (not Result): the codegen maps a Rust Result to
    // returnType "LogosResult", which the host marshals to null in the UI; a
    // plain String maps to QString and passes through. Errors are {"error":...}.
    fn capture_attestation(&mut self, id_commitment_hex: String) -> String {
        capture_attestation_impl(id_commitment_hex).unwrap_or_else(|e| json!({ "error": e }).to_string())
    }
    fn card_status(&mut self) -> String {
        card_status_impl().unwrap_or_else(|e| json!({ "present": false, "error": e }).to_string())
    }
}

// Drive the physical card in-process: connect -> select -> IDENTIFY bound to the
// supplied id_commitment -> verify the attestation vs the pinned production CA.
// select() leaves the secure channel closed, so identify() transmits in the
// clear — IDENTIFY_CARD is public and needs no pair/PIN.
fn capture_attestation_impl(id_commitment_hex: String) -> Result<String, String> {
    let idc_bytes = parse_hex32("id_commitment", &id_commitment_hex)?;
    let challenge = bound_challenge(&idc_bytes);

    let mut kc = Keycard::connect()?;
    kc.select()?;
    if !kc.initialized {
        return Err("card is not initialized".into());
    }
    let tlv = kc.identify(&challenge)?;

    let att = parse_attestation(&tlv).map_err(|e| format!("parse attestation: {e}"))?;
    let nullifier = verify_attestation(&att, &[STATUS_PRODUCTION_CA], &challenge)
        .map_err(|e| format!("attestation not verified: {e}"))?;

    Ok(json!({
        "id_commitment": hex::encode(idc_bytes),
        "attestation_tlv": hex::encode(&tlv),
        "nullifier": hex::encode(nullifier),
        "verified": true,
    })
    .to_string())
}

// Poll the reader for card presence via SCardGetStatusChange — no card session,
// so it never resets the card (unlike connect+select at poll rate).
fn card_status_impl() -> Result<String, String> {
    let present = reader_card_present()?;
    Ok(json!({ "present": present }).to_string())
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<KeycardCapture>();
}
