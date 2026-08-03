// Gifter NODE (server): mount /logos/rln/membership/1.0.0 over libp2p_module's
// generic protocol bridge, authenticate each request through the configured
// vector's verifier module (rln_auth_vector contract — this module ships no
// vector of its own), and register the membership on-chain via
// liblogos_rln_module. A single serialized worker drains inbound streams so
// the funded wallet's tx nonce stays ordered.
// FEATURE: RLN membership gifter server

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use rln_auth_vector::VerifyRequest;
use serde_json::{json, Value};

use crate::auth;
use crate::lp::{self, b64, b64_decode};
use crate::wire::{
    MembershipAllocationFailure, MembershipAllocationSuccess, RlnGifterRequest, RlnGifterResponse,
    RLN_GIFTER_CODEC,
};

// The accept poll blocks on the C++ side up to this long, then loops.
const ACCEPT_TIMEOUT_MS: i32 = 3_600_000;
const READ_TIMEOUT_MS: i32 = 60_000;
const WRITE_TIMEOUT_MS: i32 = 30_000;
const REGISTER_TIMEOUT_MS: i32 = 190_000;
const MOUNT_TIMEOUT_MS: i32 = 30_000;
// Verifier modules may do their own IO (chain reads, HTTP), so the budget
// is generous.
const AUTH_VERIFY_TIMEOUT_MS: i32 = 30_000;
const DEFAULT_MAX_RATE: u64 = 100;
const MAX_RPC_SIZE: u64 = 4096;

#[derive(Clone)]
struct ServerCfg {
    config: String,
    wallet: String,
    /// Vector verifiers: authentication_type → (module, opaque per-vector
    /// config). Every vector — the reference keycard/eth modules included —
    /// is a plugin implementing the rln_auth_vector verifier contract; this
    /// module ships none of its own, so a new allocation-auth strategy needs
    /// zero changes here. Empty map = open gifter (auth skipped entirely).
    auth_verifiers: HashMap<String, (String, Option<Value>)>,
    nullifiers_path: String,
    max_rate_limit: u64,
}

static SERVER: Mutex<Option<ServerCfg>> = Mutex::new(None);
static CONSUMED_NULLIFIERS: Mutex<Option<HashSet<String>>> = Mutex::new(None);
static SERVING: AtomicBool = AtomicBool::new(false);

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn blob(v: Value) -> Value {
    // Single JSON-blob arg wrapped in a positional args array, as the
    // JSON-blob methods on libp2p_module expect.
    json!([v.to_string()])
}

/// Server entry point (the trait's `serve`): args
/// `{config, wallet, authVerifiers?, consumedNullifiersPath?, maxRateLimit?}`.
/// `authVerifiers` maps each accepted authentication_type to its verifier
/// module — `{"<type>": {"module": "<logos module>", "config"?: {…}}}` —
/// an rln_auth_vector VERIFY_METHOD implementor, called per request with the
/// operator's opaque `config` riding along. A verdict nullifier gets shared
/// reserve/rollback/persist replay protection. No authVerifiers = an OPEN
/// gifter (every request registers).
/// Mounts the protocol and starts the serialized serve worker. Returns `{mounted:true}`.
pub fn serve(args_json: &str) -> Result<Value, String> {
    let a: Value = serde_json::from_str(args_json).map_err(|e| format!("serve args: {e}"))?;
    let config = a.get("config").and_then(Value::as_str).ok_or("missing config")?.to_string();
    let wallet = a.get("wallet").and_then(Value::as_str).ok_or("missing wallet")?.to_string();
    let max_rate_limit = a.get("maxRateLimit").and_then(Value::as_u64).unwrap_or(DEFAULT_MAX_RATE);
    let nullifiers_path =
        a.get("consumedNullifiersPath").and_then(Value::as_str).unwrap_or("").to_string();

    // A present-but-malformed authVerifiers must fail serve, never silently
    // degrade to an open gifter.
    let mut auth_verifiers: HashMap<String, (String, Option<Value>)> = HashMap::new();
    match a.get("authVerifiers") {
        None | Some(Value::Null) => {}
        Some(Value::Object(map)) => {
            for (atype, v) in map {
                let module = v.get("module").and_then(Value::as_str).unwrap_or("");
                if module.is_empty() {
                    return Err(format!("authVerifiers['{atype}'] needs a module"));
                }
                // Open the verifier's lp client HERE, on the owner thread —
                // the serve worker cannot create clients, only use them.
                lp::ensure_client(module).map_err(|e| format!("authVerifiers['{atype}']: {e}"))?;
                auth_verifiers
                    .insert(atype.clone(), (module.to_string(), v.get("config").cloned()));
            }
        }
        Some(_) => return Err("authVerifiers must be an object of {type: {module, config?}}".into()),
    }

    // Merge, never replace: a re-serve (config refresh) may only ADD replay
    // knowledge, or in-memory reservations would be forgotten.
    lock(&CONSUMED_NULLIFIERS)
        .get_or_insert_with(HashSet::new)
        .extend(auth::load_nullifiers(&nullifiers_path));
    *lock(&SERVER) = Some(ServerCfg {
        config,
        wallet,
        auth_verifiers,
        nullifiers_path,
        max_rate_limit,
    });

    // Mount + spawn the serialized worker exactly once; re-calling serve just
    // refreshes the config above (e.g. a new wallet or verifier set).
    if !SERVING.swap(true, Ordering::SeqCst) {
        if let Err(e) = lp::call_libp2p("mountProtocol", &json!([RLN_GIFTER_CODEC]), MOUNT_TIMEOUT_MS) {
            SERVING.store(false, Ordering::SeqCst);
            return Err(format!("mountProtocol: {e}"));
        }
        std::thread::spawn(worker_loop);
    }
    Ok(json!({ "mounted": true }))
}

// One serialized worker: accept → read → auth → register → respond, one request
// at a time. Serializing register_member keeps the funded wallet nonce ordered.
fn worker_loop() {
    loop {
        // call_libp2p unwraps the StdLogosResult envelope {success,error,value}
        // and returns the inner value ({streamId, proto}).
        let accept = lp::call_libp2p(
            "protocolAcceptStream",
            &blob(json!({ "proto": RLN_GIFTER_CODEC, "timeoutMs": ACCEPT_TIMEOUT_MS })),
            ACCEPT_TIMEOUT_MS,
        );
        let stream_id = match &accept {
            Ok(v) => v.get("streamId").and_then(Value::as_u64),
            Err(_) => None, // timeout / transient — poll again
        };
        let Some(stream_id) = stream_id else {
            eprintln!("rln_gifter serve: accept had no streamId: {accept:?}");
            continue;
        };
        if let Err(e) = handle_stream(stream_id) {
            eprintln!("rln_gifter serve: stream {stream_id}: {e}");
        }
    }
}

fn handle_stream(stream_id: u64) -> Result<(), String> {
    let read = lp::call_libp2p(
        "streamReadLpJson",
        &blob(json!({ "streamId": stream_id, "maxSize": MAX_RPC_SIZE, "timeoutMs": READ_TIMEOUT_MS })),
        READ_TIMEOUT_MS + 10_000,
    )?;
    let data_b64 = read.get("dataB64").and_then(Value::as_str).ok_or("streamReadLpJson: no dataB64")?;
    let req_bytes = b64_decode(data_b64)?;

    let resp = handle_request(&req_bytes);

    // Write the response, then release the server stream. Never send EOF/close
    // from the server side (yamux cleanup races in the FFI host); the client
    // released its side after reading.
    let _ = lp::call_libp2p(
        "streamWriteLpJson",
        &blob(json!({ "streamId": stream_id, "dataB64": b64(&resp.encode()) })),
        WRITE_TIMEOUT_MS + 10_000,
    );
    let _ = lp::call_libp2p(
        "streamReleaseJson",
        &blob(json!({ "streamId": stream_id })),
        10_000,
    );
    Ok(())
}

fn failure_response(request_id: &str, auth_success: bool, message: &str) -> RlnGifterResponse {
    RlnGifterResponse {
        request_id: request_id.to_string(),
        auth_success,
        error: Some(message.to_string()),
        success: None,
        failure: Some(MembershipAllocationFailure { error_message: message.to_string() }),
    }
}

// Handle one decoded request: authenticate through the configured vector's
// verifier module, register on-chain, and roll back the nullifier
// reservation if registration fails.
fn handle_request(buf: &[u8]) -> RlnGifterResponse {
    let req: RlnGifterRequest = match RlnGifterRequest::decode(buf) {
        Ok(r) => r,
        Err(e) => return failure_response("N/A", false, &format!("decode error: {e}")),
    };

    if req.identity_commitment.len() != 32 {
        return failure_response(&req.request_id, true, "identity_commitment must be 32 bytes");
    }

    let Some(cfg) = lock(&SERVER).clone() else {
        return failure_response(&req.request_id, true, "gifter not configured");
    };

    let auth_type = String::from_utf8_lossy(&req.authentication_type).to_string();
    let mut authorized_nullifier: Option<String> = None;

    // The effective rate is settled BEFORE verification so the verifier
    // judges the number that will actually be registered. The operator cap
    // applies to every request, whatever the vector's replay choices.
    let mut rate = req.rate_limit.unwrap_or(DEFAULT_MAX_RATE);
    if rate > cfg.max_rate_limit {
        rate = cfg.max_rate_limit;
    }

    if !cfg.auth_verifiers.is_empty() {
        // Delegate the decision to the vector's verifier module (an
        // rln_auth_vector VERIFY_METHOD implementor). The operator's opaque
        // per-vector config rides along on every call, so verifiers stay
        // stateless. Payload plausibility is the verifier's business — this
        // module carries bytes, it doesn't judge them.
        let Some((module, verifier_config)) = cfg.auth_verifiers.get(&auth_type) else {
            return failure_response(
                &req.request_id,
                false,
                &format!("unsupported authentication_type: '{auth_type}'"),
            );
        };
        let verify_req = VerifyRequest {
            auth_type: auth_type.clone(),
            payload_hex: hex::encode(&req.authentication_payload),
            id_commitment_hex: hex::encode(&req.identity_commitment),
            rate,
            config: verifier_config.clone(),
        };
        let verify_json = match serde_json::to_string(&verify_req) {
            Ok(s) => s,
            Err(e) => return failure_response(&req.request_id, false, &format!("verify request: {e}")),
        };
        let reply = match lp::call_module_json(
            module,
            rln_auth_vector::VERIFY_METHOD,
            &json!([verify_json]),
            AUTH_VERIFY_TIMEOUT_MS,
        ) {
            Ok(r) => r,
            Err(e) => {
                return failure_response(
                    &req.request_id,
                    false,
                    &format!("auth verifier {module}: {e}"),
                )
            }
        };
        let verdict = match rln_auth_vector::parse_verdict(&reply) {
            Ok(v) => v,
            Err(e) => {
                return failure_response(
                    &req.request_id,
                    false,
                    &format!("auth verifier {module}: {e}"),
                )
            }
        };
        if !verdict.ok {
            let reason = verdict.reason.as_deref().unwrap_or("verifier rejected the request");
            return failure_response(&req.request_id, false, reason);
        }
        // A verdict nullifier opts in to the shared replay protection:
        // reserve BEFORE the register await so a concurrent request spending
        // the same credential can't also pass; rolled back on register
        // failure, persisted on success. Normalized once at this trust
        // boundary (the load path lowercases too, so restart survives any
        // plugin's casing) and namespaced by vector, so no vector can spend
        // or squat another vector's credentials in the shared store.
        if let Some(nul) = verdict.nullifier {
            let nul = nul.trim().to_lowercase();
            if nul.is_empty() || nul.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return failure_response(
                    &req.request_id,
                    false,
                    &format!("auth verifier {module}: malformed nullifier"),
                );
            }
            let nul = format!("{auth_type}:{nul}");
            let mut g = lock(&CONSUMED_NULLIFIERS);
            let set = g.get_or_insert_with(HashSet::new);
            if set.contains(&nul) {
                return failure_response(
                    &req.request_id,
                    false,
                    &format!("credential already used: {nul}"),
                );
            }
            set.insert(nul.clone());
            authorized_nullifier = Some(nul);
        }
    }

    match register(&cfg, &req.identity_commitment, rate) {
        Ok(success) => {
            if let Some(nul) = &authorized_nullifier {
                auth::append_nullifier(&cfg.nullifiers_path, nul);
            }
            RlnGifterResponse {
                request_id: req.request_id,
                auth_success: true,
                error: None,
                success: Some(success),
                failure: None,
            }
        }
        Err(e) => {
            if let Some(nul) = &authorized_nullifier {
                if let Some(set) = lock(&CONSUMED_NULLIFIERS).as_mut() {
                    set.remove(nul);
                }
            }
            RlnGifterResponse {
                request_id: req.request_id,
                auth_success: true,
                error: None,
                success: None,
                failure: Some(MembershipAllocationFailure { error_message: e }),
            }
        }
    }
}

// Delegate the on-chain registration to liblogos_rln_module (the funded wallet
// stays there). Runs on the serialized worker thread → lp_invoke_async.
fn register(cfg: &ServerCfg, id_commitment: &[u8], rate: u64) -> Result<MembershipAllocationSuccess, String> {
    let idc_hex = hex::encode(id_commitment);
    let reply = lp::call_module_json(
        lp::RLN_MODULE,
        "register_member",
        &json!([cfg.config, cfg.wallet, idc_hex, rate]),
        REGISTER_TIMEOUT_MS,
    )?;
    let leaf_index = reply
        .get("leaf_index")
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("register_member: no leaf_index in {reply}"))?;

    // tx_result is a JSON STRING nesting {tx_hash,...}; surface the hash so the
    // client can show it. Absent for an already-registered PDA.
    let mut tx_hash_bytes = Vec::new();
    if let Some(tx_result) = reply.get("tx_result").and_then(Value::as_str) {
        if let Ok(inner) = serde_json::from_str::<Value>(tx_result) {
            if let Some(txh) = inner.get("tx_hash").and_then(Value::as_str) {
                tx_hash_bytes = hex::decode(txh.trim_start_matches("0x")).unwrap_or_default();
            }
        }
    }

    Ok(MembershipAllocationSuccess {
        leaf_index,
        merkle_root: Vec::new(),
        block_number: 0,
        transaction_hash: tx_hash_bytes,
        config_account_id: Some(cfg.config.clone()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Under the test FFI stub no lp client can open, which is exactly the
    // shape of a misconfigured verifier: serve must surface it, not defer it
    // to a per-request auth failure.
    #[test]
    fn serve_fails_loudly_when_a_verifier_client_cannot_open() {
        let e = serve(
            r#"{"config":"c","wallet":"w","authVerifiers":{"t":{"module":"nope_module"}}}"#,
        )
        .unwrap_err();
        assert!(e.contains("authVerifiers['t']"), "got: {e}");
    }

    #[test]
    fn serve_rejects_malformed_auth_verifiers_instead_of_degrading_open() {
        let e = serve(r#"{"config":"c","wallet":"w","authVerifiers":"oops"}"#).unwrap_err();
        assert!(e.contains("must be an object"), "got: {e}");
        let e = serve(r#"{"config":"c","wallet":"w","authVerifiers":{"t":{}}}"#).unwrap_err();
        assert!(e.contains("needs a module"), "got: {e}");
    }
}
