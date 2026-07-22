// Gifter NODE (server): mount /logos/rln/membership/1.0.0 over libp2p_module's
// generic protocol bridge, authenticate each request (eth allowlist / keycard
// attestation), and register the membership on-chain via liblogos_rln_module.
// Replaces libp2p_module.rlnGifterServe + the gifter cbind. A single serialized
// worker drains inbound streams so the funded wallet's tx nonce stays ordered.
// FEATURE: RLN membership gifter server

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use serde_json::{json, Value};

use crate::auth;
use crate::lp::{self, b64, b64_decode};
use crate::wire::{
    MembershipAllocationFailure, MembershipAllocationSuccess, RlnGifterRequest, RlnGifterResponse,
    ETH_ALLOWLIST_AUTH_TYPE, KEYCARD_ATTEST_AUTH_TYPE, RLN_GIFTER_CODEC,
};

// The accept poll blocks on the C++ side up to this long, then loops.
const ACCEPT_TIMEOUT_MS: i32 = 3_600_000;
const READ_TIMEOUT_MS: i32 = 60_000;
const WRITE_TIMEOUT_MS: i32 = 30_000;
const REGISTER_TIMEOUT_MS: i32 = 190_000;
const MOUNT_TIMEOUT_MS: i32 = 30_000;
const DEFAULT_MAX_RATE: u64 = 100;
const MAX_RPC_SIZE: u64 = 4096;

#[derive(Clone)]
struct ServerCfg {
    config: String,
    wallet: String,
    trusted_cas: Vec<[u8; 33]>,
    allowlist: HashSet<String>,
    nullifiers_path: String,
    max_rate_limit: u64,
    auth_enabled: bool,
}

static SERVER: Mutex<Option<ServerCfg>> = Mutex::new(None);
static CONSUMED_NULLIFIERS: Mutex<Option<HashSet<String>>> = Mutex::new(None);
static CONSUMED_ADDRESSES: Mutex<Option<HashSet<String>>> = Mutex::new(None);
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
/// `{config, wallet, allowlist?, trustedCAs?, consumedNullifiersPath?, maxRateLimit?}`.
/// Mounts the protocol and starts the serialized serve worker. Returns `{mounted:true}`.
pub fn serve(args_json: &str) -> Result<Value, String> {
    let a: Value = serde_json::from_str(args_json).map_err(|e| format!("serve args: {e}"))?;
    let config = a.get("config").and_then(Value::as_str).ok_or("missing config")?.to_string();
    let wallet = a.get("wallet").and_then(Value::as_str).ok_or("missing wallet")?.to_string();
    let max_rate_limit = a.get("maxRateLimit").and_then(Value::as_u64).unwrap_or(DEFAULT_MAX_RATE);
    let nullifiers_path =
        a.get("consumedNullifiersPath").and_then(Value::as_str).unwrap_or("").to_string();

    let mut allowlist = HashSet::new();
    if let Some(arr) = a.get("allowlist").and_then(Value::as_array) {
        for e in arr {
            if let Some(s) = e.as_str() {
                allowlist.insert(s.to_lowercase());
            }
        }
    }
    let mut trusted_cas: Vec<[u8; 33]> = Vec::new();
    if let Some(arr) = a.get("trustedCAs").and_then(Value::as_array) {
        for e in arr {
            if let Some(s) = e.as_str() {
                let bytes = hex::decode(s.trim_start_matches("0x"))
                    .map_err(|e| format!("trustedCA hex: {e}"))?;
                let ca: [u8; 33] =
                    bytes.as_slice().try_into().map_err(|_| "trustedCA must be 33 bytes")?;
                trusted_cas.push(ca);
            }
        }
    }
    let auth_enabled = !allowlist.is_empty() || !trusted_cas.is_empty();

    *lock(&CONSUMED_NULLIFIERS) = Some(auth::load_nullifiers(&nullifiers_path));
    {
        let mut g = lock(&CONSUMED_ADDRESSES);
        if g.is_none() {
            *g = Some(HashSet::new());
        }
    }
    *lock(&SERVER) = Some(ServerCfg {
        config,
        wallet,
        trusted_cas,
        allowlist,
        nullifiers_path,
        max_rate_limit,
        auth_enabled,
    });

    // Mount + spawn the serialized worker exactly once; re-calling serve just
    // refreshes the config above (e.g. a new wallet or allowlist).
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

// Ports protocol.nim handleRequest: authenticate (one-shot per address/card),
// clamp keycard grants, register on-chain, and roll back the nullifier
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
    let mut authorized_signer: Option<String> = None;
    let mut authorized_nullifier: Option<String> = None;

    if cfg.auth_enabled {
        if req.authentication_payload.is_empty() {
            return failure_response(&req.request_id, false, "missing authentication_payload");
        }
        if auth_type == ETH_ALLOWLIST_AUTH_TYPE && !cfg.allowlist.is_empty() {
            let signer = match auth::verify_eip191(&req.identity_commitment, &req.authentication_payload) {
                Ok(s) => s,
                Err(e) => return failure_response(&req.request_id, false, &format!("signature verification failed: {e}")),
            };
            if !cfg.allowlist.contains(&signer) {
                return failure_response(&req.request_id, false, &format!("address not allowlisted: {signer}"));
            }
            let already = lock(&CONSUMED_ADDRESSES).as_ref().map(|s| s.contains(&signer)).unwrap_or(false);
            if already {
                return failure_response(&req.request_id, false, &format!("address already used: {signer}"));
            }
            authorized_signer = Some(signer);
        } else if auth_type == KEYCARD_ATTEST_AUTH_TYPE && !cfg.trusted_cas.is_empty() {
            let nul = match auth::verify_keycard(&req.authentication_payload, &req.identity_commitment, &cfg.trusted_cas) {
                Ok(n) => n,
                Err(e) => return failure_response(&req.request_id, false, &e),
            };
            // Reserve the nullifier BEFORE the register await so a concurrent
            // request with the same card can't also pass; rolled back on failure.
            {
                let mut g = lock(&CONSUMED_NULLIFIERS);
                let set = g.get_or_insert_with(HashSet::new);
                if set.contains(&nul) {
                    return failure_response(&req.request_id, false, &format!("card already used: {nul}"));
                }
                set.insert(nul.clone());
            }
            authorized_nullifier = Some(nul);
        } else {
            return failure_response(&req.request_id, false, &format!("unsupported authentication_type: '{auth_type}'"));
        }
    }

    let mut rate = req.rate_limit.unwrap_or(100);
    if authorized_nullifier.is_some() && rate > cfg.max_rate_limit {
        rate = cfg.max_rate_limit;
    }

    match register(&cfg, &req.identity_commitment, rate) {
        Ok(success) => {
            if let Some(signer) = authorized_signer {
                lock(&CONSUMED_ADDRESSES).get_or_insert_with(HashSet::new).insert(signer);
            }
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
