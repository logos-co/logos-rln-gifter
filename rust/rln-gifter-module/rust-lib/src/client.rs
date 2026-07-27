// Gifter CLIENT: generate an RLN identity locally, request a gifted membership
// from a gifter peer over libp2p, and adopt the granted leaf. Replaces
// libp2p_module.rlnGifterRequest — the protocol now runs over libp2p_module's
// GENERIC protocolRequest bridge, with no gifter code in that module.
// FEATURE: RLN membership gifter client

use serde_json::{json, Value};

use crate::lp::{self, b64, b64_decode};
use crate::wire::{RlnGifterRequest, RlnGifterResponse, KEYCARD_ATTEST_AUTH_TYPE, RLN_GIFTER_CODEC};

// generate_identity is fast; the gifter round trip (dial + on-chain register on
// the server) can run up to ~3 minutes; adoption is a quick local set.
const GEN_TIMEOUT_MS: i32 = 30_000;
const REQUEST_TIMEOUT_MS: i64 = 190_000;
const REQUEST_CALL_TIMEOUT_MS: i32 = 205_000;

/// Client entry point (the trait's `request`): args
/// `{gifterPeerId, gifterMultiaddr, config?, seed, rate?, authKey?, attestation?}`.
/// Returns `{leaf_index, id_commitment, auth_success, identity_adopted, tx_hash?, config_account?}`.
pub fn request(args_json: &str) -> Result<Value, String> {
    let a: Value = serde_json::from_str(args_json).map_err(|e| format!("request args: {e}"))?;
    let gifter_peer_id = a.get("gifterPeerId").and_then(Value::as_str).ok_or("missing gifterPeerId")?;
    let gifter_multiaddr =
        a.get("gifterMultiaddr").and_then(Value::as_str).ok_or("missing gifterMultiaddr")?;
    let seed = a.get("seed").and_then(Value::as_str).ok_or("missing seed")?;
    let rate = a.get("rate").and_then(Value::as_u64).unwrap_or(0);
    let auth_key = a.get("authKey").and_then(Value::as_str).unwrap_or("");
    let attestation = a.get("attestation").and_then(Value::as_str).unwrap_or("");

    // 1. Generate the RLN identity locally — the secret hash never leaves here.
    let idv = lp::call_module_json(lp::RLN_MODULE, "generate_identity", &json!([seed]), GEN_TIMEOUT_MS)?;
    let id_commitment_hex = idv
        .get("id_commitment")
        .and_then(Value::as_str)
        .ok_or("generate_identity: no id_commitment")?
        .to_string();
    let id_commitment =
        hex::decode(&id_commitment_hex).map_err(|e| format!("id_commitment hex: {e}"))?;

    // 2. Auth payload: the keycard attestation TLV (passthrough) or, for the
    //    eth-allowlist path, an EIP-191 signature (client-side signing TBD).
    let (auth_type, auth_payload) = if !attestation.is_empty() {
        let tlv = hex::decode(attestation.trim_start_matches("0x"))
            .map_err(|e| format!("attestation hex: {e}"))?;
        (KEYCARD_ATTEST_AUTH_TYPE, tlv)
    } else if !auth_key.is_empty() {
        return Err("eth-allowlist client signing is not implemented in rln_gifter_module".into());
    } else {
        // Open gifter (empty allowlist / no auth): send an empty keycard payload.
        (KEYCARD_ATTEST_AUTH_TYPE, Vec::new())
    };

    // 3. One request→response over the generic libp2p bridge.
    let request_id = format!("gift-{}", &id_commitment_hex[..id_commitment_hex.len().min(16)]);
    let req = RlnGifterRequest {
        request_id: request_id.clone(),
        authentication_type: auth_type.as_bytes().to_vec(),
        authentication_payload: auth_payload,
        identity_commitment: id_commitment,
        rate_limit: if rate > 0 { Some(rate) } else { None },
    };
    let pr_args = json!({
        "peerId": gifter_peer_id,
        "multiaddrs": [gifter_multiaddr],
        "proto": RLN_GIFTER_CODEC,
        "requestB64": b64(&req.encode()),
        "timeoutMs": REQUEST_TIMEOUT_MS,
    });
    let pr = lp::call_libp2p("protocolRequest", &json!([pr_args.to_string()]), REQUEST_CALL_TIMEOUT_MS)?;
    let resp_b64 = pr
        .get("responseB64")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("protocolRequest: no responseB64 in {pr}"))?;
    let resp = RlnGifterResponse::decode(&b64_decode(resp_b64)?)?;

    if resp.request_id != request_id {
        return Err("gifter response requestId mismatch".into());
    }
    if !resp.auth_success {
        return Err(resp
            .error
            .or_else(|| resp.failure.as_ref().map(|f| f.error_message.clone()))
            .unwrap_or_else(|| "gifter authentication failed".into()));
    }
    let success = resp.success.ok_or_else(|| {
        resp.failure
            .as_ref()
            .map(|f| f.error_message.clone())
            .or(resp.error.clone())
            .unwrap_or_else(|| "gifter returned no membership".into())
    })?;

    let leaf_index = success.leaf_index;
    let tx_hash = hex::encode(&success.transaction_hash);

    // The gifter membership flow sends no mix-RLN messages, so there is no
    // identity to adopt into a mix/proof subsystem, and the client runs against a
    // PLAIN libp2p node (vanilla upstream) that has no such surface. The app
    // persists the credential to its keystore from its own generate_identity.
    let identity_adopted = false;

    let mut out = json!({
        "leaf_index": leaf_index,
        "id_commitment": id_commitment_hex,
        "auth_success": true,
        "identity_adopted": identity_adopted,
    });
    if !tx_hash.is_empty() {
        out["tx_hash"] = json!(tx_hash);
    }
    if let Some(cfg) = success.config_account_id {
        out["config_account"] = json!(cfg);
    }
    Ok(out)
}
