// Gifter CLIENT: request a gifted membership for an identity commitment from
// a gifter peer over libp2p_module's generic protocolRequest bridge. The
// commitment is normally supplied by the caller (the RLN membership module,
// which keeps the identity secret). Auth is vector-agnostic: the payload is
// supplied raw or produced by an rln_auth_vector provider module named in the
// request — this module knows no vector by name.
// FEATURE: RLN membership gifter client

use rln_auth_vector::ProduceRequest;
use serde_json::{json, Value};

use crate::lp::{self, b64, b64_decode};
use crate::wire::{RlnGifterRequest, RlnGifterResponse, RLN_GIFTER_CODEC};

// generate_identity is fast; the gifter round trip (dial + on-chain register on
// the server) can run up to ~3 minutes; adoption is a quick local set.
const GEN_TIMEOUT_MS: i32 = 30_000;
const REQUEST_TIMEOUT_MS: i64 = 190_000;
const REQUEST_CALL_TIMEOUT_MS: i32 = 205_000;
// Producer plugins may drive hardware (keycard capture covers
// connect+select+IDENTIFY plus a slow tap), so the budget is generous.
const PRODUCE_TIMEOUT_MS: i32 = 120_000;

/// Client entry point (the trait's `request`): args
/// `{gifterPeerId, gifterMultiaddr, config?, identityCommitment?, seed?, rate?,
///  authType?, authPayload?, authProvider?, authArgs?}`.
/// Returns `{leaf_index, id_commitment, auth_success, identity_adopted, tx_hash?, config_account?}`.
pub fn request(args_json: &str) -> Result<Value, String> {
    let a: Value = serde_json::from_str(args_json).map_err(|e| format!("request args: {e}"))?;
    let gifter_peer_id = a.get("gifterPeerId").and_then(Value::as_str).ok_or("missing gifterPeerId")?;
    let gifter_multiaddr =
        a.get("gifterMultiaddr").and_then(Value::as_str).ok_or("missing gifterMultiaddr")?;
    let seed = a.get("seed").and_then(Value::as_str).unwrap_or("");
    let provided_commitment =
        a.get("identityCommitment").and_then(Value::as_str).unwrap_or("");
    let rate = a.get("rate").and_then(Value::as_u64).unwrap_or(0);

    // 1. Obtain the RLN identity commitment. Preferred (full spec alignment):
    //    the caller — the RLN membership module — generated the credential
    //    in-module and passes its commitment here, so the identity secret never
    //    leaves that module. Legacy fallback: derive it from a seed via the
    //    sibling's generate_identity.
    let id_commitment_hex = if !provided_commitment.is_empty() {
        provided_commitment.trim_start_matches("0x").to_string()
    } else if !seed.is_empty() {
        let idv =
            lp::call_module_json(lp::RLN_MODULE, "generate_identity", &json!([seed]), GEN_TIMEOUT_MS)?;
        idv.get("id_commitment")
            .and_then(Value::as_str)
            .ok_or("generate_identity: no id_commitment")?
            .to_string()
    } else {
        return Err("request needs identityCommitment or seed".into());
    };
    let id_commitment =
        hex::decode(&id_commitment_hex).map_err(|e| format!("id_commitment hex: {e}"))?;

    // 2. Auth vector + payload. `authType` names the vector in the wire's
    //    OPEN authentication_type vocabulary — any type the target gifter is
    //    configured to verify (its authVerifiers modules); this client never
    //    gatekeeps it and knows no vector by name. The payload comes from
    //    `authPayload` (raw hex, verbatim — material the application produced
    //    itself, e.g. an external wallet signature) or from an `authProvider`
    //    module implementing the rln_auth_vector producer contract
    //    (PRODUCE_METHOD, `authArgs` forwarded verbatim — e.g. keycard
    //    capture). No authType at all is an UNAUTHENTICATED request for an
    //    open gifter: empty type, empty payload.
    let auth_type_req = a.get("authType").and_then(Value::as_str).unwrap_or("");
    let auth_payload_hex = a.get("authPayload").and_then(Value::as_str).unwrap_or("");
    let auth_provider = a.get("authProvider").and_then(Value::as_str).unwrap_or("");
    let auth_payload: Vec<u8> = if auth_type_req.is_empty() {
        if !auth_payload_hex.is_empty() || !auth_provider.is_empty() {
            return Err("authPayload/authProvider need an explicit authType".into());
        }
        Vec::new()
    } else if !auth_payload_hex.is_empty() {
        hex::decode(auth_payload_hex.trim_start_matches("0x"))
            .map_err(|e| format!("authPayload hex: {e}"))?
    } else if !auth_provider.is_empty() {
        let prod_req = ProduceRequest {
            auth_type: auth_type_req.to_string(),
            id_commitment_hex: id_commitment_hex.clone(),
            args: a.get("authArgs").cloned(),
        };
        let prod_json =
            serde_json::to_string(&prod_req).map_err(|e| format!("produce request: {e}"))?;
        let reply = lp::call_module_json(
            auth_provider,
            rln_auth_vector::PRODUCE_METHOD,
            &json!([prod_json]),
            PRODUCE_TIMEOUT_MS,
        )?;
        let reply = rln_auth_vector::parse_produce_reply(&reply)
            .map_err(|e| format!("auth provider {auth_provider}: {e}"))?;
        hex::decode(reply.payload_hex.trim_start_matches("0x"))
            .map_err(|e| format!("auth provider payload hex: {e}"))?
    } else {
        return Err(format!("authType '{auth_type_req}' needs authPayload or authProvider"));
    };

    // 3. One request→response over the generic libp2p bridge.
    let request_id = format!("gift-{}", &id_commitment_hex[..id_commitment_hex.len().min(16)]);
    let req = RlnGifterRequest {
        request_id: request_id.clone(),
        authentication_type: auth_type_req.as_bytes().to_vec(),
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
