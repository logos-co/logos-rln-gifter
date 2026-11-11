// Allocator (server): mount /logos/rln/membership/1.0.0 over libp2p_module's
// generic protocol bridge, authenticate each request through the configured
// vector's verifier module (rln_auth_vector contract — this module ships no
// vector of its own), and register the membership on-chain via
// liblogos_lez_rln_module. A single serialized worker drains inbound streams so
// the funded payer's tx nonce stays ordered.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use rln_auth_vector::VerifyRequestRef;
use serde_json::{json, Value};

use crate::auth;
use crate::lp::{self, b64, b64_decode, lock};
use crate::wire::{
    canonical_account, service_data, MembershipAllocationFailure, MembershipAllocationSuccess,
    RlnGifterRequest, RlnGifterResponse, RLN_GIFTER_CODEC, RLN_GIFTER_SERVICE_ID,
};

// The accept poll blocks libp2p_module's call dispatcher (a condvar wait in
// `protocolAcceptStream`): while one is pending the module answers nothing
// else, from anyone. Short, so the worker can run the discovery calls a
// re-serve asks for between two accepts; a timed-out accept is idle, not an
// error.
const ACCEPT_TIMEOUT_MS: i32 = 2_000;
const ACCEPT_IDLE: &str = "timeout waiting for inbound stream";
// The lp call outlives libp2p's own accept timeout by this much: a caller
// that gives up first while libp2p pops the stream a moment later loses that
// request (the stream is dequeued, nobody reads it).
const ACCEPT_CALL_MARGIN_MS: i32 = 3_000;
const READ_TIMEOUT_MS: i32 = 60_000;
const WRITE_TIMEOUT_MS: i32 = 30_000;
const REGISTER_TIMEOUT_MS: i32 = 190_000;
/// How long a submitted registration may take to show up on chain before the
/// request is answered as unconfirmed, unless `serve` names another
/// (`confirmBudgetSec`), and how often the registry is read meanwhile. The
/// client allows REQUEST_TIMEOUT_MS (190 s) for the whole exchange, so a
/// budget much above this default makes the client give up before the
/// answer; one registration fits per block.
const DEFAULT_CONFIRM_BUDGET_S: u64 = 150;
const CONFIRM_POLL_S: u64 = 2;
const GET_MEMBERSHIP_TIMEOUT_MS: i32 = 30_000;
const MOUNT_TIMEOUT_MS: i32 = 30_000;
const ADVERTISE_TIMEOUT_MS: i32 = 30_000;
/// The worker reads the outbound peer count at most this often.
const PEER_CHECK_S: u64 = 10;
/// A caller-supplied record is published verbatim and never refreshed by
/// libp2p (ad lifetime 900 s), so the worker re-places it at this age.
const AD_REFRESH_S: u64 = 600;
// Verifier modules may do their own IO (chain reads, HTTP), so the budget
// is generous.
const AUTH_VERIFY_TIMEOUT_MS: i32 = 30_000;
const DEFAULT_MAX_RATE: u64 = 100;
const MAX_RPC_SIZE: u64 = 4096;

#[derive(Debug)]
struct RegistryCfg {
    max_rate_limit: u64,
}

struct ServerCfg {
    /// The registry a request naming none is served on.
    default_config: String,
    /// Every served registry (ConfigState account, lowercase) with its own
    /// rate cap; the default one included.
    registries: HashMap<String, RegistryCfg>,
    /// Seconds a submitted registration may take to show on chain before the
    /// request is answered as unconfirmed.
    confirm_budget_s: u64,
    /// Vector verifiers: authentication_type → (module, opaque per-vector
    /// config). Every vector — the reference keycard/eth modules included —
    /// is a plugin implementing the rln_auth_vector verifier contract; this
    /// module ships none of its own, so a new allocation-auth strategy needs
    /// zero changes here. Empty map = open allocator (auth skipped entirely).
    auth_verifiers: HashMap<String, (String, Option<Value>)>,
}

impl ServerCfg {
    /// The registry a request asks for (its field 100, else the default) and
    /// that registry's rate cap; `Err` names a registry this allocator does not
    /// serve.
    fn resolve_registry(&self, requested: Option<&str>) -> Result<(String, u64), String> {
        let registry = match requested.map(str::trim).filter(|s| !s.is_empty()) {
            Some(r) => canonical_account(r).map_err(|e| format!("registry: {e}"))?,
            // OWNERSHIP: the resolved registry is owned (a requested one is
            // canonicalised into a new String), so the default is a copy.
            None => self.default_config.clone(),
        };
        match self.registries.get(&registry) {
            Some(r) => Ok((registry, r.max_rate_limit)),
            None => Err(format!("registry not served: {registry}")),
        }
    }
}

/// `serve`'s registries: the default `config` plus each `registries` entry
/// (`"<config>"` with the global cap, or `{"config", "maxRateLimit"?}`), as
/// canonical accounts, in order; a repeated one is an operator mistake.
fn parse_registries(
    a: &Value,
    default_config: &str,
    global_cap: u64,
) -> Result<(HashMap<String, RegistryCfg>, Vec<String>), String> {
    let mut map = HashMap::new();
    let mut order = Vec::new();
    let mut add = |config: &str, cap: u64| -> Result<(), String> {
        let key = canonical_account(config).map_err(|e| format!("registries: {e}"))?;
        // OWNERSHIP: the map and the order list each keep the key.
        if map
            .insert(
                key.clone(),
                RegistryCfg {
                    max_rate_limit: cap,
                },
            )
            .is_some()
        {
            return Err(format!("registries: {key} is listed twice"));
        }
        order.push(key);
        Ok(())
    };
    add(default_config, global_cap)?;
    match a.get("registries") {
        None | Some(Value::Null) => {}
        Some(Value::Array(items)) => {
            for item in items {
                match item {
                    Value::String(s) => add(s, global_cap)?,
                    Value::Object(o) => {
                        let config = o
                            .get("config")
                            .and_then(Value::as_str)
                            .ok_or("registries: an object entry needs a config")?;
                        let cap = match o.get("maxRateLimit") {
                            None | Some(Value::Null) => global_cap,
                            Some(v) => v
                                .as_u64()
                                .ok_or("registries: maxRateLimit must be an unsigned integer")?,
                        };
                        add(config, cap)?;
                    }
                    _ => return Err(
                        r#"registries must be an array of "<config>" | {config, maxRateLimit?}"#
                            .into(),
                    ),
                }
            }
        }
        Some(_) => {
            return Err(
                r#"registries must be an array of "<config>" | {config, maxRateLimit?}"#.into(),
            )
        }
    }
    Ok((map, order))
}

/// The configuration of the latest `serve`.
// OWNERSHIP: `serve` swaps in a whole new config; each request takes a cheap
// Arc handle and keeps the config it started with while the lock is free.
static SERVER: Mutex<Option<Arc<ServerCfg>>> = Mutex::new(None);
// OWNERSHIP: one store for the process, shared by `serve` on the owner thread
// (merge, file change) and the worker (reserve, release); its methods do file
// IO only and no libp2p or module call runs under this lock, so the owner
// thread waits at most for a file write.
static NULLIFIERS: LazyLock<Mutex<auth::NullifierStore>> = LazyLock::new(Mutex::default);
/// What an advertisement carries: the service data, and the addresses of a
/// caller-supplied record (`createXpr`) or None for libp2p's self-built one.
#[derive(Clone, Debug, PartialEq)]
struct AdSpec {
    data: String,
    addrs: Option<Vec<String>>,
}

/// A placed advertisement: what, when (unix s), and the outbound peer count
/// last seen since.
#[derive(Debug)]
struct Placed {
    spec: AdSpec,
    at: u64,
    peers: usize,
}

/// The advertisement this node should place (None = nothing): a latest-value
/// mailbox `serve` writes and the advertiser reads.
// OWNERSHIP: crosses from `serve` on the owner thread to the worker; never
// locked across a libp2p call.
static WANTED_AD: Mutex<Option<AdSpec>> = Mutex::new(None);
/// What the advertiser has placed, published after its libp2p calls return:
/// a re-serve compares its wish with it instead of waiting on those calls.
// OWNERSHIP: written by the advertiser's owner (`serve`, then the worker),
// read by `serve`; never locked across a libp2p call.
static PLACED_AD: Mutex<Option<AdSpec>> = Mutex::new(None);

/// The advertisement upkeep and what it has placed. One owner at a time:
/// `serve` until the worker exists, then the worker, which takes it by
/// value, so its state needs no lock.
#[derive(Default)]
struct Advertiser {
    placed: Option<Placed>,
    /// When the outbound peer count was last read (unix s).
    peers_checked_at: u64,
    /// The seqNo of the last caller-supplied record placed.
    last_seq_no: u64,
}

/// `serve`'s state, a field of the module on the owner thread.
pub struct ServeState {
    /// Whether the gifter protocol is mounted.
    mounted: bool,
    /// The advertiser while `serve` drives it; `None` once the serve worker
    /// owns it and is libp2p_module's only caller.
    advertiser: Option<Advertiser>,
}

impl Default for ServeState {
    fn default() -> Self {
        ServeState {
            mounted: false,
            advertiser: Some(Advertiser::default()),
        }
    }
}

fn blob(v: &Value) -> Value {
    // Single JSON-blob arg wrapped in a positional args array, as the
    // JSON-blob methods on libp2p_module expect.
    json!([v.to_string()])
}

/// The (registry, auth type) pairs a configuration serves, in the order
/// `serve` lists its registries; an open allocator serves the empty type.
fn served_pairs<'a>(
    served: &'a [String],
    auth_verifiers: &'a HashMap<String, (String, Option<Value>)>,
) -> Vec<(&'a str, &'a str)> {
    let mut types: Vec<&str> = auth_verifiers.keys().map(String::as_str).collect();
    types.sort_unstable();
    if types.is_empty() {
        types.push("");
    }
    served
        .iter()
        .flat_map(|r| types.iter().map(move |t| (r.as_str(), *t)))
        .collect()
}

/// A signed record for `addrs` carrying `data` under the service id, as the
/// base64 `createXpr` returns.
fn create_xpr(addrs: &[String], data: &str, seq_no: u64) -> Result<String, String> {
    let mut services = serde_json::Map::new();
    services.insert(RLN_GIFTER_SERVICE_ID.to_string(), lp::bstr(data.as_bytes()));
    let v = lp::call_libp2p(
        "createXpr",
        &json!([addrs, services, seq_no]),
        ADVERTISE_TIMEOUT_MS,
    )
    .map_err(|e| format!("createXpr: {e}"))?;
    v.as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("createXpr: no record in {v}"))
}

impl Advertiser {
    /// Bring the advertisement in line with `WANTED_AD`: the one service id,
    /// the served pairs in its data. A changed advertisement, or `renew`,
    /// stops the placed one first (libp2p refuses to replace one in place);
    /// an unchanged one is left alone. A caller-supplied record gets a seqNo
    /// above every earlier one. `peers` is the outbound peer count it is
    /// placed with. Called where libp2p_module can answer: by `serve` before
    /// the worker exists, by the worker between accepts afterwards.
    fn reconcile(&mut self, renew: bool, peers: usize) -> Result<(), String> {
        let wanted = {
            let wanted = lock(&WANTED_AD);
            if !renew && self.placed.as_ref().map(|p| &p.spec) == wanted.as_ref() {
                return Ok(());
            }
            // OWNERSHIP: the advertiser places its own copy of the wish; the
            // mailbox is unlocked before the libp2p calls.
            wanted.clone()
        };
        if self.placed.is_some() {
            lp::call_libp2p(
                "discoStopAdvertising",
                &json!([RLN_GIFTER_SERVICE_ID]),
                ADVERTISE_TIMEOUT_MS,
            )
            .map_err(|e| format!("discoStopAdvertising: {e}"))?;
            self.placed = None;
            *lock(&PLACED_AD) = None;
        }
        if let Some(spec) = wanted {
            let at = lp::now_s();
            let seq_no = at.max(self.last_seq_no + 1);
            let record = match &spec.addrs {
                Some(addrs) => create_xpr(addrs, &spec.data, seq_no)?,
                None => String::new(),
            };
            lp::call_libp2p(
                "discoStartAdvertising",
                &json!([RLN_GIFTER_SERVICE_ID, spec.data.as_str(), record]),
                ADVERTISE_TIMEOUT_MS,
            )
            .map_err(|e| format!("discoStartAdvertising: {e}"))?;
            if spec.addrs.is_some() {
                self.last_seq_no = seq_no;
            }
            self.peers_checked_at = at;
            // OWNERSHIP: `serve` reads the published copy; the advertiser
            // keeps the placed one.
            *lock(&PLACED_AD) = Some(spec.clone());
            self.placed = Some(Placed { spec, at, peers });
        }
        Ok(())
    }

    /// The worker's advertisement upkeep between two accepts: apply a
    /// re-serve's change, and re-place an unchanged advertisement once
    /// outbound peers appear after it was placed with none (its registration
    /// reached nobody) or once a caller-supplied record reaches
    /// `AD_REFRESH_S`. The peer count is read at most every `PEER_CHECK_S`.
    fn tick(&mut self) -> Result<(), String> {
        let now = lp::now_s();
        let mut peers = self.placed.as_ref().map(|p| p.peers).unwrap_or(0);
        let mut renew = false;
        if let Some(p) = &mut self.placed {
            if now >= self.peers_checked_at + PEER_CHECK_S {
                self.peers_checked_at = now;
                if let Ok(n) = lp::outbound_peers() {
                    renew |= p.peers == 0 && n > 0;
                    peers = n;
                    p.peers = n;
                }
            }
            renew |= p.spec.addrs.is_some() && now >= p.at + AD_REFRESH_S;
        }
        self.reconcile(renew, peers)
    }
}

/// Server entry point (the trait's `serve`): args
/// `{config, registries?, authVerifiers?, consumedNullifiersPath?,
///  maxRateLimit?, confirmBudgetSec?, advertise?, advertiseAddrs?}`.
/// `wallet` is accepted and ignored: every registration is paid by the
/// registry module's own payer (`REGISTRY_MODULE_PAYER`).
/// `config` is the registry a request naming none is served on; `registries`
/// adds further served ones (`"<config>"`, or `{"config", "maxRateLimit"?}`
/// for a cap of its own) — a request names its registry on the wire and one
/// this allocator does not serve is refused before any verifier runs.
/// `authVerifiers` maps each accepted authentication_type to its verifier
/// module — `{"<type>": {"module": "<logos module>", "config"?: {…}}}` —
/// an rln_auth_vector VERIFY_METHOD implementor, called per request with the
/// operator's opaque `config` riding along and the requester's transport peer
/// id. A verdict nullifier gets shared reserve/rollback/persist replay
/// protection, scoped per registry. No authVerifiers = an OPEN allocator (every
/// request registers).
/// `advertise` (default true) publishes the served (registry, auth type)
/// pairs through libp2p service discovery under `RLN_GIFTER_SERVICE_ID` so
/// clients find this allocator without a configured peer id; the node must
/// have discovery mounted (`mountServiceDiscovery`) and a registrar peer in
/// its routing table. Left to its default, a node without discovery serves
/// unadvertised and the reply says why; an explicit `true` makes that an
/// error. At most 8 pairs fit an advertisement. `advertiseAddrs` (multiaddr
/// strings) advertises a record built for those addresses (`createXpr`),
/// which libp2p never refreshes, so the worker re-places it every
/// `AD_REFRESH_S`; absent, libp2p builds and republishes the record from its
/// listen addresses. The advertisement is placed at once, never waiting
/// for peers; `advertisedToPeers` is the outbound peer count then (its
/// registration reaches only connected registrars), and one placed with
/// none is re-placed by the worker once outbound peers appear. While the
/// worker serves,
/// libp2p_module answers only it, so a re-serve that changes the
/// advertisement hands the change to the worker (`advertisePending`).
/// Mounts the protocol and starts the serialized serve worker. Returns
/// `confirmBudgetSec` (default 150) is how long a submitted registration may
/// take to show on chain before the request is answered `unconfirmed: …`.
/// `{mounted:true, registries:[…], advertised:bool, advertisePending?,
///  serviceId?, serviceData?, advertisedToPeers?, advertiseError?}`.
pub fn serve(state: &mut ServeState, args_json: &str) -> Result<Value, String> {
    let mut a: Value = serde_json::from_str(args_json).map_err(|e| format!("serve args: {e}"))?;
    // Moved out of the parsed args before `config` borrows them, so the
    // verifier entries move into the stored config; the checks stay below, in
    // their original order.
    let auth_verifiers_arg = a.get_mut("authVerifiers").map(Value::take);
    let config = a
        .get("config")
        .and_then(Value::as_str)
        .ok_or("missing config")?;
    if let Some(named) = a.get("wallet").and_then(Value::as_str) {
        if !named.trim().is_empty() {
            eprintln!(
                "rln-gifter serve: wallet {named} is ignored — registrations are paid by the \
                 registry module's own payer (fund the account its wallet_status reports)"
            );
        }
    }
    let max_rate_limit = a
        .get("maxRateLimit")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_MAX_RATE);
    let confirm_budget_s = match a.get("confirmBudgetSec") {
        None | Some(Value::Null) => DEFAULT_CONFIRM_BUDGET_S,
        Some(v) => v
            .as_u64()
            .filter(|s| *s >= 1)
            .ok_or("confirmBudgetSec must be a positive integer (seconds)")?,
    };
    let nullifiers_path = a
        .get("consumedNullifiersPath")
        .and_then(Value::as_str)
        .unwrap_or("");
    let advertise_wanted = match a.get("advertise") {
        None | Some(Value::Null) => None,
        Some(Value::Bool(b)) => Some(*b),
        Some(_) => return Err("advertise must be a boolean".into()),
    };
    let advertise_addrs = match a.get("advertiseAddrs") {
        None | Some(Value::Null) => None,
        Some(Value::Array(items)) => Some(
            items
                .iter()
                .map(|v| v.as_str().map(str::to_owned))
                .collect::<Option<Vec<String>>>()
                .ok_or("advertiseAddrs must be an array of multiaddr strings")?,
        ),
        Some(_) => return Err("advertiseAddrs must be an array of multiaddr strings".into()),
    };
    let (registries, served) = parse_registries(&a, config, max_rate_limit)?;
    // OWNERSHIP: the stored config keeps its own default; `served` stays for
    // the advertisement pairs and the reply.
    let default_config = served[0].clone();

    // A present-but-malformed authVerifiers must fail serve, never silently
    // degrade to an open allocator.
    let mut auth_verifiers: HashMap<String, (String, Option<Value>)> = HashMap::new();
    match auth_verifiers_arg {
        None | Some(Value::Null) => {}
        Some(Value::Object(map)) => {
            for (atype, mut v) in map {
                let module = match v.get_mut("module").map(Value::take) {
                    Some(Value::String(m)) if !m.is_empty() => m,
                    _ => return Err(format!("authVerifiers['{atype}'] needs a module")),
                };
                // Open the verifier's lp client HERE, on the owner thread —
                // the serve worker cannot create clients, only use them.
                lp::ensure_client(&module).map_err(|e| format!("authVerifiers['{atype}']: {e}"))?;
                auth_verifiers.insert(atype, (module, v.get_mut("config").map(Value::take)));
            }
        }
        Some(_) => {
            return Err("authVerifiers must be an object of {type: {module, config?}}".into())
        }
    }

    // Refused before anything is configured: an allocator that cannot say
    // what it serves must not serve it half-advertised.
    let data = match advertise_wanted {
        Some(false) => None,
        _ => Some(service_data(&served_pairs(&served, &auth_verifiers))?),
    };

    // Merged into the spent set, never replacing it; a file other than the
    // current one inherits the set and takes every later reservation.
    lock(&NULLIFIERS)
        .open(nullifiers_path)
        .map_err(|e| format!("nullifier store: {e}"))?;
    *lock(&SERVER) = Some(Arc::new(ServerCfg {
        default_config,
        registries,
        confirm_budget_s,
        auth_verifiers,
    }));

    let mut reply = json!({ "mounted": true, "registries": served, "advertised": false });
    if let Some(data) = &data {
        reply["serviceId"] = json!(RLN_GIFTER_SERVICE_ID);
        reply["serviceData"] = json!(data);
    }
    let wanted = data.map(|data| AdSpec {
        data,
        addrs: advertise_addrs,
    });
    let Some(advertiser) = state.advertiser.as_mut() else {
        // The worker owns libp2p_module and the advertiser: it places the
        // wish between accepts. The reply compares the wish with what the
        // worker last published, so nothing here waits on its calls.
        if *lock(&PLACED_AD) == wanted {
            reply["advertised"] = json!(wanted.is_some());
        } else {
            reply["advertisePending"] = json!(true);
        }
        *lock(&WANTED_AD) = wanted;
        return Ok(reply);
    };
    *lock(&WANTED_AD) = wanted;
    // The advertisement BEFORE the mount: a serve an explicit advertise:true
    // fails must leave nothing mounted — a mounted protocol nobody accepts on
    // makes clients wait out their whole budget. The moments between the two
    // calls cost a client at most a refused dial, which it treats as "try the
    // next allocator".
    advertise_first(advertiser, &mut reply, advertise_wanted)?;
    // Mount exactly once; re-calling serve just refreshes the config above
    // (e.g. a new wallet or verifier set) and the advertisement.
    if !state.mounted {
        lp::call_libp2p(
            "mountProtocol",
            &json!([RLN_GIFTER_CODEC]),
            MOUNT_TIMEOUT_MS,
        )
        .map_err(|e| format!("mountProtocol: {e}"))?;
        state.mounted = true;
    }
    // Spawn the serialized worker exactly once, after the advertisement and
    // the mount: from here on libp2p_module answers only it.
    if let Some(advertiser) = state.advertiser.take() {
        std::thread::spawn(move || worker_loop(advertiser));
    }
    Ok(reply)
}

/// `serve`'s advertisement before the worker exists: place `WANTED_AD` at
/// once with the outbound peer count read once (0 when libp2p cannot say),
/// into `reply` as `advertised`, `advertisedToPeers` and `advertiseError`.
/// An explicit `advertise: true` makes a failure the error.
fn advertise_first(
    advertiser: &mut Advertiser,
    reply: &mut Value,
    advertise_wanted: Option<bool>,
) -> Result<(), String> {
    let wanted = lock(&WANTED_AD).is_some();
    let peers = if wanted {
        lp::outbound_peers().unwrap_or(0)
    } else {
        0
    };
    if wanted {
        reply["advertisedToPeers"] = json!(peers);
    }
    match advertiser.reconcile(false, peers) {
        Ok(()) => reply["advertised"] = json!(wanted),
        Err(e) if advertise_wanted == Some(true) => return Err(format!("advertise: {e}")),
        Err(e) => reply["advertiseError"] = json!(e),
    }
    Ok(())
}

// One serialized worker: accept → read → auth → register → respond, one request
// at a time. Serializing register_member keeps the funded wallet nonce ordered.
// Between accepts it applies the advertisement a re-serve asked for.
fn worker_loop(mut advertiser: Advertiser) {
    loop {
        if let Err(e) = advertiser.tick() {
            eprintln!("rln_gifter serve: advertisement: {e}");
        }
        // call_libp2p unwraps the StdLogosResult envelope {success,error,value}
        // and returns the inner value ({streamId, proto, peerId}; peerId since
        // libp2p_module 1.1.0 — the requester as the secure channel proved it).
        let accept = lp::call_libp2p(
            "protocolAcceptStream",
            &blob(&json!({ "proto": RLN_GIFTER_CODEC, "timeoutMs": ACCEPT_TIMEOUT_MS })),
            ACCEPT_TIMEOUT_MS + ACCEPT_CALL_MARGIN_MS,
        );
        let stream_id = match &accept {
            Ok(v) => v.get("streamId").and_then(Value::as_u64),
            Err(e) if e.contains(ACCEPT_IDLE) => continue,
            Err(_) => None, // transient — poll again
        };
        let Some(stream_id) = stream_id else {
            eprintln!("rln_gifter serve: accept had no streamId: {accept:?}");
            continue;
        };
        let peer_id = accept
            .as_ref()
            .ok()
            .and_then(|v| v.get("peerId"))
            .and_then(Value::as_str);
        if let Err(e) = handle_stream(stream_id, peer_id) {
            eprintln!("rln_gifter serve: stream {stream_id}: {e}");
        }
    }
}

fn handle_stream(stream_id: u64, peer_id: Option<&str>) -> Result<(), String> {
    let release = || {
        let _ = lp::call_libp2p(
            "streamReleaseJson",
            &blob(&json!({ "streamId": stream_id })),
            10_000,
        );
    };
    // A request that cannot be read still holds a server stream: release it,
    // or every such failure leaks one.
    let req_bytes = (|| -> Result<Vec<u8>, String> {
        let read = lp::call_libp2p(
            "streamReadLpJson",
            &blob(&json!({ "streamId": stream_id, "maxSize": MAX_RPC_SIZE, "timeoutMs": READ_TIMEOUT_MS })),
            READ_TIMEOUT_MS + 10_000,
        )?;
        let data_b64 = read.get("dataB64").and_then(Value::as_str).ok_or("streamReadLpJson: no dataB64")?;
        b64_decode(data_b64)
    })()
    .inspect_err(|_| release())?;

    let resp = handle_request(&req_bytes, peer_id);

    // Write the response, then release the server stream. Never send EOF/close
    // from the server side (yamux cleanup races in the FFI host); the client
    // released its side after reading.
    let _ = lp::call_libp2p(
        "streamWriteLpJson",
        &blob(&json!({ "streamId": stream_id, "dataB64": b64(&resp.encode()) })),
        WRITE_TIMEOUT_MS + 10_000,
    );
    let _ = lp::call_libp2p(
        "streamReleaseJson",
        &blob(&json!({ "streamId": stream_id })),
        10_000,
    );
    Ok(())
}

fn failure_response(request_id: String, auth_success: bool, message: String) -> RlnGifterResponse {
    RlnGifterResponse {
        request_id,
        auth_success,
        // OWNERSHIP: the wire carries the message twice (field 3 and the
        // failure sub-message); one copy, the original moves into the second.
        error: Some(message.clone()),
        success: None,
        failure: Some(MembershipAllocationFailure {
            error_message: message,
        }),
    }
}

// Handle one decoded request: resolve its registry, authenticate through the
// configured vector's verifier module, register on-chain, and roll back the
// nullifier reservation if registration fails. `peer_id` is the requester as
// the transport authenticated it, for vectors that judge the peer.
fn handle_request(buf: &[u8], peer_id: Option<&str>) -> RlnGifterResponse {
    let req: RlnGifterRequest = match RlnGifterRequest::decode(buf) {
        Ok(r) => r,
        Err(e) => return failure_response("N/A".to_owned(), false, format!("decode error: {e}")),
    };

    // Length AND field membership: a non-canonical commitment must never
    // reach a verifier (which would spend a nullifier reservation) or the
    // lez module (a non-canonical commitment panics the guest and the fee is
    // charged).
    if let Some(why) = crate::wire::commitment_refusal(&req.identity_commitment) {
        return failure_response(
            req.request_id,
            true,
            RegisterError::NotSubmitted(why.to_string()).message(),
        );
    }

    let Some(cfg) = lock(&SERVER).as_ref().map(Arc::clone) else {
        return failure_response(
            req.request_id,
            true,
            RegisterError::NotSubmitted("gifter not configured".to_string()).message(),
        );
    };

    // The registry first: a request for one this allocator does not serve costs
    // no verifier round-trip and no nullifier reservation.
    let (registry, max_rate_limit) = match cfg.resolve_registry(req.config_account_id.as_deref()) {
        Ok(r) => r,
        Err(why) => return failure_response(req.request_id, false, why),
    };

    let auth_type = String::from_utf8_lossy(&req.authentication_type).to_string();
    let mut authorized_nullifier: Option<String> = None;

    // The effective rate is settled BEFORE verification so the verifier
    // judges the number that will actually be registered. The registry's cap
    // applies to every request, whatever the vector's replay choices.
    let mut rate = req.rate_limit.unwrap_or(DEFAULT_MAX_RATE);
    if rate > max_rate_limit {
        rate = max_rate_limit;
    }

    if !cfg.auth_verifiers.is_empty() {
        // Delegate the decision to the vector's verifier module (an
        // rln_auth_vector VERIFY_METHOD implementor). The operator's opaque
        // per-vector config rides along on every call, so verifiers stay
        // stateless. Payload plausibility is the verifier's business — this
        // module carries bytes, it doesn't judge them.
        let Some((module, verifier_config)) = cfg.auth_verifiers.get(&auth_type) else {
            return failure_response(
                req.request_id,
                false,
                format!("unsupported authentication_type: '{auth_type}'"),
            );
        };
        let verify_req = VerifyRequestRef {
            auth_type: &auth_type,
            payload_hex: &hex::encode(&req.authentication_payload),
            id_commitment_hex: &hex::encode(&req.identity_commitment),
            rate,
            config: verifier_config.as_ref(),
            peer_id,
        };
        let verify_json = match serde_json::to_string(&verify_req) {
            Ok(s) => s,
            Err(e) => {
                return failure_response(req.request_id, false, format!("verify request: {e}"))
            }
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
                    req.request_id,
                    false,
                    format!("auth verifier {module}: {e}"),
                )
            }
        };
        let verdict = match rln_auth_vector::parse_verdict(&reply) {
            Ok(v) => v,
            Err(e) => {
                return failure_response(
                    req.request_id,
                    false,
                    format!("auth verifier {module}: {e}"),
                )
            }
        };
        if !verdict.ok {
            let reason = verdict
                .reason
                .unwrap_or_else(|| "verifier rejected the request".to_owned());
            return failure_response(req.request_id, false, reason);
        }
        // A verdict nullifier opts in to the shared replay protection:
        // reserve BEFORE the register await so a concurrent request spending
        // the same credential can't also pass, and persist the reservation at
        // once so a restart during the confirmation wait cannot grant it a
        // second membership; a registration nothing on chain saw takes the
        // reservation back. Normalized once at this trust boundary (the load
        // path lowercases too, so restart survives any plugin's casing) and
        // namespaced by registry and vector: a credential buys one membership
        // per registry, and no vector can spend or squat another vector's
        // credentials in the shared store.
        if let Some(nul) = verdict.nullifier {
            let nul = nul.trim().to_lowercase();
            if nul.is_empty() || nul.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return failure_response(
                    req.request_id,
                    false,
                    format!("auth verifier {module}: malformed nullifier"),
                );
            }
            let nul = rln_auth_vector::namespaced_nullifier(&registry, &auth_type, &nul);
            // The store is unlocked again before any module call.
            let spent = lock(&NULLIFIERS).is_spent(&nul);
            if spent {
                // The credential bought a membership already. If it bought
                // THIS commitment's — a retry after a reply the client never
                // read — the answer is that membership, and nothing new is
                // spent; any other commitment is a replay.
                if let Some(success) = registered_membership(&registry, &req.identity_commitment) {
                    return RlnGifterResponse {
                        request_id: req.request_id,
                        auth_success: true,
                        error: None,
                        success: Some(success),
                        failure: None,
                    };
                }
                return failure_response(
                    req.request_id,
                    false,
                    format!("credential already used: {nul}"),
                );
            }
            let reserved = lock(&NULLIFIERS).reserve(&nul);
            match reserved {
                Ok(true) => {}
                Ok(false) => {
                    return failure_response(
                        req.request_id,
                        false,
                        format!("credential already used: {nul}"),
                    )
                }
                // A reservation that never reached disk does not survive a
                // restart, so nothing is registered against it.
                Err(e) => {
                    return failure_response(
                        req.request_id,
                        true,
                        RegisterError::NotSubmitted(format!("nullifier store: {e}")).message(),
                    )
                }
            }
            authorized_nullifier = Some(nul);
        }
    }

    match register(
        &registry,
        &req.identity_commitment,
        rate,
        cfg.confirm_budget_s,
    ) {
        Ok(success) => RlnGifterResponse {
            request_id: req.request_id,
            auth_success: true,
            error: None,
            success: Some(success),
            failure: None,
        },
        Err(e) => {
            let mut store_note = String::new();
            if let Some(nul) = &authorized_nullifier {
                match e {
                    // Nothing reached the chain: the credential is unspent.
                    RegisterError::NotSubmitted(_) => {
                        // The release stays in memory either way; a store
                        // that kept the line keeps the credential spent
                        // across a restart, and the reply says so.
                        let released = lock(&NULLIFIERS).release(nul);
                        if let Err(store) = released {
                            store_note = format!("; nullifier store: {store}");
                        }
                    }
                    // The registration may still land: the reservation stays,
                    // in memory and on disk.
                    RegisterError::Unconfirmed(_) => {}
                }
            }
            RlnGifterResponse {
                request_id: req.request_id,
                auth_success: true,
                error: None,
                success: None,
                failure: Some(MembershipAllocationFailure {
                    error_message: format!("{}{store_note}", e.message()),
                }),
            }
        }
    }
}

/// Why a gift was not delivered: before anything was submitted, or after a
/// submission (made, or asked for with no answer) the registry did not
/// confirm in time.
enum RegisterError {
    NotSubmitted(String),
    Unconfirmed(String),
}

impl RegisterError {
    fn message(self) -> String {
        match self {
            RegisterError::NotSubmitted(m) => format!("{}{m}", crate::wire::NOT_SUBMITTED_PREFIX),
            RegisterError::Unconfirmed(m) => format!("{}{m}", crate::wire::UNCONFIRMED_PREFIX),
        }
    }
}

/// The usable membership the registry holds for a commitment, as a grant,
/// or None when there is none (not registered, expired, or unreadable).
fn registered_membership(
    registry: &str,
    id_commitment: &[u8],
) -> Option<MembershipAllocationSuccess> {
    let m = lp::call_module_json(
        lp::LEZ_RLN_MODULE,
        "get_membership",
        &json!([registry, hex::encode(id_commitment)]),
        GET_MEMBERSHIP_TIMEOUT_MS,
    )
    .ok()?;
    Some(MembershipAllocationSuccess {
        leaf_index: confirmed_leaf(&m)?,
        merkle_root: Vec::new(),
        block_number: 0,
        transaction_hash: Vec::new(),
        config_account_id: Some(registry.to_string()),
    })
}

/// The registry module's refusal to submit, `{"error":"<kind>: <reason>"}`.
fn refusal(reply: &Value) -> Option<&str> {
    reply.get("error").and_then(Value::as_str)
}

/// The leaf of a membership the registry shows as usable, from a
/// `get_membership` reply `{"registered":true,"state":…,"leaf_index":N,…}`;
/// None while it is not registered, or registered but expired: a grant of an
/// expired leaf would spend the credential on a membership no proof can use.
fn confirmed_leaf(reply: &Value) -> Option<u64> {
    if reply.get("registered").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    match reply.get("state").and_then(Value::as_str) {
        Some("active") | Some("grace_period") => {}
        _ => return None,
    }
    reply.get("leaf_index").and_then(Value::as_u64)
}

/// The payer argument of `register_member` meaning "the registry module's own
/// payer". That module reserves the fee from its own payer whatever account
/// is named and preflights only the named one, so naming another account
/// splits price and fee across two accounts with one of them unchecked.
const REGISTRY_MODULE_PAYER: &str = "";

// Delegate the on-chain registration to liblogos_lez_rln_module, paid by that
// module's own payer, then wait until the registry shows
// the membership. register_member answers when the transaction is accepted:
// its leaf_index is only a pre-submit estimate (the tree assigns the leaf), and
// a registration whose claims went stale is re-sent by that module under a new
// transaction. So the leaf reported to the client is read back from the chain.
// Runs on the serialized worker thread -> lp_invoke_async.
fn register(
    registry: &str,
    id_commitment: &[u8],
    rate: u64,
    confirm_budget_s: u64,
) -> Result<MembershipAllocationSuccess, RegisterError> {
    let idc_hex = hex::encode(id_commitment);
    let reply = lp::call_module_json_classified(
        lp::LEZ_RLN_MODULE,
        "register_member",
        &json!([registry, REGISTRY_MODULE_PAYER, idc_hex, rate]),
        REGISTER_TIMEOUT_MS,
    )
    .map_err(|e| match e {
        // The registry module never ran the call, or answered it.
        lp::CallError::Failed(m) => RegisterError::NotSubmitted(m),
        // No answer: the registry module may have accepted the transaction.
        lp::CallError::Unanswered(m) => {
            RegisterError::Unconfirmed(format!("{m}; it may still land"))
        }
    })?;
    // liblogos_lez_rln_module answers {"error":…} for a registration its
    // program would reject (a commitment that is not a field element, a full
    // registry, a payer that cannot pay) and for a send the sequencer did not
    // accept: nothing will land.
    if let Some(why) = refusal(&reply) {
        return Err(RegisterError::NotSubmitted(format!(
            "register_member refused: {why}"
        )));
    }
    // A commitment already on this registry: the registry module submits
    // nothing and reports the leaf. A usable membership is the grant; an
    // expired one is a refusal, and the credential stays unspent.
    if reply.get("already_registered").and_then(Value::as_bool) == Some(true) {
        let m = lp::call_module_json(
            lp::LEZ_RLN_MODULE,
            "get_membership",
            &json!([registry, idc_hex]),
            GET_MEMBERSHIP_TIMEOUT_MS,
        )
        .map_err(RegisterError::NotSubmitted)?;
        return match confirmed_leaf(&m) {
            Some(leaf_index) => Ok(MembershipAllocationSuccess {
                leaf_index,
                merkle_root: Vec::new(),
                block_number: 0,
                transaction_hash: Vec::new(),
                config_account_id: Some(registry.to_string()),
            }),
            None => Err(RegisterError::NotSubmitted(format!(
                "commitment already registered on {registry} with a membership in state {}",
                m.get("state").and_then(Value::as_str).unwrap_or("unknown")
            ))),
        };
    }

    // tx_result is a JSON STRING nesting {tx_hash,...}: the submitted
    // transaction. Absent for an already-registered PDA.
    let mut tx_hash_bytes = Vec::new();
    if let Some(tx_result) = reply.get("tx_result").and_then(Value::as_str) {
        if let Ok(inner) = serde_json::from_str::<Value>(tx_result) {
            if let Some(txh) = inner.get("tx_hash").and_then(Value::as_str) {
                tx_hash_bytes = hex::decode(txh.trim_start_matches("0x")).unwrap_or_default();
            }
        }
    }

    let deadline = lp::now_s() + confirm_budget_s;
    loop {
        if let Ok(m) = lp::call_module_json(
            lp::LEZ_RLN_MODULE,
            "get_membership",
            &json!([registry, idc_hex]),
            GET_MEMBERSHIP_TIMEOUT_MS,
        ) {
            if let Some(leaf_index) = confirmed_leaf(&m) {
                return Ok(MembershipAllocationSuccess {
                    leaf_index,
                    merkle_root: Vec::new(),
                    block_number: 0,
                    transaction_hash: tx_hash_bytes,
                    config_account_id: Some(registry.to_string()),
                });
            }
        }
        if lp::now_s() >= deadline {
            return Err(RegisterError::Unconfirmed(format!(
                "registration submitted (tx {}) but not on chain within {confirm_budget_s}s; it may still land",
                hex::encode(&tx_hash_bytes)
            )));
        }
        lp::sleep_s(CONFIRM_POLL_S);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    fn acct(b: u8) -> String {
        hex::encode([b; 32])
    }

    /// `serve` on a module that has not served before.
    fn serve(args_json: &str) -> Result<Value, String> {
        super::serve(&mut ServeState::default(), args_json)
    }

    fn served(a: &Value) -> Arc<ServerCfg> {
        let (registries, served) = parse_registries(a, &acct(0xd).to_uppercase(), 100).unwrap();
        Arc::new(ServerCfg {
            default_config: served[0].clone(),
            registries,
            confirm_budget_s: DEFAULT_CONFIRM_BUDGET_S,
            auth_verifiers: HashMap::new(),
        })
    }

    #[test]
    fn registries_are_the_default_plus_each_entry_with_its_own_cap() {
        let (d, m, x) = (acct(0xd), acct(0xab), acct(0xb));
        // The mix account in base58 (32 bytes of 0xab).
        let m_b58 = "CZ8YUVdk7znjrUmnb5n7kgySk9yRAsQDYmyCxzfSky9t";
        let cfg = served(&json!({ "registries": [m_b58, { "config": x, "maxRateLimit": 20 }] }));
        assert_eq!(cfg.resolve_registry(None).unwrap(), (d.clone(), 100));
        assert_eq!(
            cfg.resolve_registry(Some(&format!(" {} ", m.to_uppercase())))
                .unwrap(),
            (m.clone(), 100)
        );
        assert_eq!(cfg.resolve_registry(Some(m_b58)).unwrap(), (m.clone(), 100));
        assert_eq!(cfg.resolve_registry(Some(&x)).unwrap(), (x.clone(), 20));
        assert_eq!(cfg.resolve_registry(Some("")).unwrap().0, d);
        let y = acct(0xc);
        assert_eq!(
            cfg.resolve_registry(Some(&y)).unwrap_err(),
            format!("registry not served: {y}")
        );
        assert!(cfg
            .resolve_registry(Some("nope"))
            .unwrap_err()
            .starts_with("registry: config account 'nope'"));
        let (_, order) = parse_registries(&json!({ "registries": [m_b58] }), &d, 1).unwrap();
        assert_eq!(order, [d.clone(), m]);
        let (_, order) = parse_registries(&json!({}), &d, 1).unwrap();
        assert_eq!(order, [d]);
    }

    #[test]
    fn the_served_pairs_are_every_registry_with_every_verifier_type() {
        let (d, m) = (acct(0xd), acct(0xa));
        let mut verifiers = HashMap::new();
        verifiers.insert(
            "peer-any".to_string(),
            ("rln_auth_module".to_string(), None),
        );
        verifiers.insert(
            "eth-allowlist".to_string(),
            ("rln_auth_module".to_string(), None),
        );
        let registries = [d.clone(), m.clone()];
        let pairs = served_pairs(&registries, &verifiers);
        assert_eq!(
            pairs,
            [
                (d.as_str(), "eth-allowlist"),
                (d.as_str(), "peer-any"),
                (m.as_str(), "eth-allowlist"),
                (m.as_str(), "peer-any"),
            ]
        );
        // An open allocator serves the empty type on each registry.
        assert_eq!(
            served_pairs(std::slice::from_ref(&d), &HashMap::new()),
            [(d.as_str(), "")]
        );
    }

    #[test]
    fn serve_refuses_more_pairs_than_an_advertisement_carries() {
        let regs: Vec<String> = (1..=9u8).map(acct).collect();
        let a = format!(
            r#"{{"config":"{}","wallet":"w","registries":{}}}"#,
            regs[0],
            serde_json::to_string(&regs[1..]).unwrap()
        );
        let e = serve(&a).unwrap_err();
        assert!(e.contains("at most 8"), "got: {e}");
    }

    #[test]
    fn serve_rejects_a_non_boolean_advertise() {
        let e = serve(&format!(
            r#"{{"config":"{}","wallet":"w","advertise":"yes"}}"#,
            acct(1)
        ))
        .unwrap_err();
        assert!(e.contains("advertise must be a boolean"), "got: {e}");
    }

    #[test]
    fn malformed_registries_fail_serve() {
        let (d, m) = (acct(0xd), acct(0xa));
        for (a, needle) in [
            (json!({ "registries": [d.to_uppercase()] }), "listed twice"),
            (
                json!({ "registries": [{ "maxRateLimit": 5 }] }),
                "needs a config",
            ),
            (
                json!({ "registries": [{ "config": m, "maxRateLimit": "5" }] }),
                "unsigned integer",
            ),
            (json!({ "registries": [7] }), "must be an array"),
            (json!({ "registries": m }), "must be an array"),
            (json!({ "registries": [" "] }), "config account ''"),
        ] {
            let e = parse_registries(&a, &d, 1).unwrap_err();
            assert!(e.contains(needle), "{a}: {e}");
        }
        assert!(parse_registries(&json!({}), "D", 1)
            .unwrap_err()
            .contains("config account 'D'"));
    }

    #[test]
    fn an_unserved_registry_is_refused_before_anything_else() {
        let _g = lock(&AD_STATE);
        *lock(&SERVER) = Some(served(&json!({})));
        let mut idc = vec![0xab; 32];
        idc[31] = 0x0a;
        let req = RlnGifterRequest {
            request_id: "r".into(),
            identity_commitment: idc,
            config_account_id: Some(acct(0xe)),
            ..Default::default()
        };
        let resp = handle_request(&req.encode(), None);
        assert!(!resp.auth_success);
        assert_eq!(
            resp.error.as_deref(),
            Some(format!("registry not served: {}", acct(0xe)).as_str())
        );
        *lock(&SERVER) = None;
    }

    #[test]
    fn failure_messages_say_whether_anything_was_submitted() {
        assert_eq!(
            RegisterError::NotSubmitted("x".into()).message(),
            "not submitted: x"
        );
        assert_eq!(
            RegisterError::Unconfirmed("y".into()).message(),
            "unconfirmed: y"
        );
    }

    #[test]
    fn a_refused_registration_is_recognised() {
        let r = json!({"error": "invalid_commitment: not a BN254 field element"});
        assert_eq!(
            refusal(&r),
            Some("invalid_commitment: not a BN254 field element")
        );
        assert_eq!(refusal(&json!({"leaf_index": 3, "pending": true})), None);
    }

    #[test]
    fn only_a_usable_registered_membership_has_a_confirmed_leaf() {
        assert_eq!(
            confirmed_leaf(&json!({"registered": true, "leaf_index": 7, "state": "active"})),
            Some(7)
        );
        assert_eq!(
            confirmed_leaf(&json!({"registered": true, "leaf_index": 7, "state": "grace_period"})),
            Some(7)
        );
        assert_eq!(
            confirmed_leaf(&json!({"registered": true, "leaf_index": 7, "state": "expired"})),
            None
        );
        assert_eq!(
            confirmed_leaf(&json!({"registered": true, "leaf_index": 7})),
            None
        );
        assert_eq!(confirmed_leaf(&json!({"registered": false})), None);
        assert_eq!(confirmed_leaf(&json!({"registered": true})), None);
        assert_eq!(confirmed_leaf(&json!("")), None);
    }

    // Under the test FFI stub no lp client can open, which is exactly the
    // shape of a misconfigured verifier: serve must surface it, not defer it
    // to a per-request auth failure.
    #[test]
    fn serve_fails_loudly_when_a_verifier_client_cannot_open() {
        let e = serve(&format!(
            r#"{{"config":"{}","wallet":"w","authVerifiers":{{"t":{{"module":"nope_module"}}}}}}"#,
            acct(1)
        ))
        .unwrap_err();
        assert!(e.contains("authVerifiers['t']"), "got: {e}");
    }

    #[test]
    fn serve_rejects_malformed_auth_verifiers_instead_of_degrading_open() {
        let base = format!(r#""config":"{}","wallet":"w""#, acct(1));
        let e = serve(&format!(r#"{{{base},"authVerifiers":"oops"}}"#)).unwrap_err();
        assert!(e.contains("must be an object"), "got: {e}");
        let e = serve(&format!(r#"{{{base},"authVerifiers":{{"t":{{}}}}}}"#)).unwrap_err();
        assert!(e.contains("needs a module"), "got: {e}");
        let e = serve(r#"{"config":"c","wallet":"w"}"#).unwrap_err();
        assert!(e.contains("config account 'c'"), "got: {e}");
    }

    // The advertisement statics are process-wide; tests that set them hold this.
    static AD_STATE: Mutex<()> = Mutex::new(());

    fn reset_ads() {
        *lock(&WANTED_AD) = None;
        *lock(&PLACED_AD) = None;
    }

    /// A libp2p that accepts every advertisement verb, connects `peers()`
    /// outbound peers, signs any record as "XPRB64" and refuses the mount.
    fn scripted_libp2p(peers: impl Fn() -> usize + Send + 'static) {
        lp::fake::install(Box::new(move |_, method, _| match method {
            "connectedPeers" => Ok(json!((0..peers())
                .map(|i| format!("P{i}"))
                .collect::<Vec<_>>())),
            "createXpr" => Ok(json!({ "success": true, "value": "XPRB64", "error": "" })),
            "discoStartAdvertising" | "discoStopAdvertising" => Ok(json!(true)),
            "mountProtocol" => Err("refused in test".into()),
            m => Err(format!("unscripted {m}")),
        }));
    }

    fn ad_calls() -> Vec<(String, Value)> {
        lp::fake::calls()
            .into_iter()
            .filter(|(m, _)| m != "connectedPeers")
            .collect()
    }

    #[test]
    fn advertise_addrs_place_a_record_signed_for_them() {
        let _g = lock(&AD_STATE);
        reset_ads();
        scripted_libp2p(|| 1);
        let addrs = ["/ip4/203.0.113.7/tcp/4001"];
        let e = serve(
            &json!({ "config": acct(1), "wallet": "w", "advertiseAddrs": addrs }).to_string(),
        )
        .unwrap_err();
        assert_eq!(e, "mountProtocol: refused in test");
        let data = service_data(&[(acct(1).as_str(), "")]).unwrap();
        let b64url = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            data.as_bytes(),
        );
        assert_eq!(
            ad_calls(),
            [
                (
                    "createXpr".to_string(),
                    json!([addrs, { RLN_GIFTER_SERVICE_ID: { "_bytes": b64url } }, lp::fake::START_S])
                ),
                (
                    "discoStartAdvertising".to_string(),
                    json!([RLN_GIFTER_SERVICE_ID, data, "XPRB64"])
                ),
                ("mountProtocol".to_string(), json!([RLN_GIFTER_CODEC])),
            ]
        );
        assert_eq!(lp::fake::methods()[0], "connectedPeers");
        let e =
            serve(&json!({ "config": acct(1), "wallet": "w", "advertiseAddrs": [7] }).to_string())
                .unwrap_err();
        assert!(e.contains("advertiseAddrs must be an array"), "got: {e}");
        lp::fake::clear();
        reset_ads();
    }

    #[test]
    fn without_advertise_addrs_libp2p_builds_the_record() {
        let _g = lock(&AD_STATE);
        reset_ads();
        scripted_libp2p(|| 1);
        let _ = serve(&json!({ "config": acct(1), "wallet": "w" }).to_string());
        let data = service_data(&[(acct(1).as_str(), "")]).unwrap();
        assert_eq!(
            ad_calls()[0],
            (
                "discoStartAdvertising".to_string(),
                json!([RLN_GIFTER_SERVICE_ID, data, ""])
            )
        );
        lp::fake::clear();
        reset_ads();
    }

    #[test]
    fn the_first_advertisement_is_placed_at_once_and_re_placed_when_peers_appear() {
        let _g = lock(&AD_STATE);
        let start = lp::fake::START_S;
        let spec = AdSpec {
            data: "1abc".into(),
            addrs: None,
        };

        // Two peers up: placed with them, one peer read, no wait.
        reset_ads();
        scripted_libp2p(|| 2);
        *lock(&WANTED_AD) = Some(spec.clone());
        let mut reply = json!({});
        advertise_first(&mut Advertiser::default(), &mut reply, None).unwrap();
        assert_eq!(reply, json!({ "advertised": true, "advertisedToPeers": 2 }));
        assert_eq!(
            lp::fake::methods(),
            ["connectedPeers", "discoStartAdvertising"]
        );
        assert_eq!(lp::now_s(), start);

        // libp2p cannot count peers: placed with 0 regardless.
        reset_ads();
        lp::fake::install(Box::new(|_, m, _| match m {
            "connectedPeers" => Err("connectedPeers: libp2p down".into()),
            _ => Ok(json!(true)),
        }));
        *lock(&WANTED_AD) = Some(spec.clone());
        let mut reply = json!({});
        advertise_first(&mut Advertiser::default(), &mut reply, None).unwrap();
        assert_eq!(reply, json!({ "advertised": true, "advertisedToPeers": 0 }));
        assert_eq!(lp::now_s(), start);

        // No peer yet: placed with 0 at once, then the worker re-places it
        // once peers appear.
        reset_ads();
        let up = std::sync::Arc::new(AtomicBool::new(false));
        let u = std::sync::Arc::clone(&up);
        scripted_libp2p(move || usize::from(u.load(Ordering::SeqCst)));
        *lock(&WANTED_AD) = Some(spec);
        let mut reply = json!({});
        let mut adv = Advertiser::default();
        advertise_first(&mut adv, &mut reply, None).unwrap();
        assert_eq!(reply, json!({ "advertised": true, "advertisedToPeers": 0 }));
        assert_eq!(lp::now_s(), start);
        assert_eq!(ad_calls().len(), 1);
        up.store(true, Ordering::SeqCst);
        lp::fake::advance(PEER_CHECK_S);
        adv.tick().unwrap();
        let methods: Vec<String> = ad_calls().into_iter().map(|(m, _)| m).collect();
        assert_eq!(
            methods,
            [
                "discoStartAdvertising",
                "discoStopAdvertising",
                "discoStartAdvertising"
            ]
        );
        assert_eq!(adv.placed.as_ref().map(|p| p.peers), Some(1));
        lp::fake::clear();
        reset_ads();
    }

    #[test]
    fn the_worker_re_places_the_advertisement_when_peers_appear_or_it_ages() {
        use std::sync::atomic::AtomicUsize;
        use std::sync::Arc;
        let _g = lock(&AD_STATE);
        let start = lp::fake::START_S;
        let peers = Arc::new(AtomicUsize::new(0));
        let place = |addrs: Option<Vec<String>>, peers: usize| {
            reset_ads();
            let spec = AdSpec {
                data: "1abc".into(),
                addrs,
            };
            *lock(&WANTED_AD) = Some(spec.clone());
            Advertiser {
                placed: Some(Placed {
                    spec,
                    at: start,
                    peers,
                }),
                peers_checked_at: start,
                last_seq_no: 0,
            }
        };
        let ad_methods = || ad_calls().into_iter().map(|(m, _)| m).collect::<Vec<_>>();

        // Placed with no peer: the check is rate-limited, re-places on 0 → 1
        // and only then.
        let mut adv = place(None, 0);
        let p = Arc::clone(&peers);
        scripted_libp2p(move || p.load(Ordering::SeqCst));
        lp::fake::advance(5);
        adv.tick().unwrap();
        assert!(lp::fake::calls().is_empty());
        lp::fake::advance(5);
        adv.tick().unwrap();
        assert_eq!(lp::fake::methods(), ["connectedPeers"]);
        peers.store(1, Ordering::SeqCst);
        adv.tick().unwrap();
        assert_eq!(
            lp::fake::methods(),
            ["connectedPeers"],
            "within PEER_CHECK_S of the last check"
        );
        lp::fake::advance(PEER_CHECK_S);
        adv.tick().unwrap();
        assert_eq!(
            ad_methods(),
            ["discoStopAdvertising", "discoStartAdvertising"]
        );
        lp::fake::advance(PEER_CHECK_S);
        adv.tick().unwrap();
        assert_eq!(
            ad_methods().len(),
            2,
            "peers stayed up: nothing to re-place"
        );

        // A self-built record is never re-placed for age.
        let mut adv = place(None, 1);
        scripted_libp2p(|| 1);
        lp::fake::advance(AD_REFRESH_S * 2);
        adv.tick().unwrap();
        assert!(ad_methods().is_empty());

        // A caller-supplied record is, at AD_REFRESH_S, under a fresh seqNo.
        let addrs = vec!["/ip4/203.0.113.7/tcp/4001".to_string()];
        let mut adv = place(Some(addrs), 1);
        scripted_libp2p(|| 1);
        lp::fake::advance(AD_REFRESH_S - 1);
        adv.tick().unwrap();
        assert!(ad_methods().is_empty());
        lp::fake::advance(1);
        adv.tick().unwrap();
        let calls = ad_calls();
        assert_eq!(
            calls.iter().map(|(m, _)| m.as_str()).collect::<Vec<_>>(),
            ["discoStopAdvertising", "createXpr", "discoStartAdvertising"]
        );
        assert_eq!(calls[1].1[2], json!(start + AD_REFRESH_S));
        assert_eq!(
            adv.placed.as_ref().map(|p| p.at),
            Some(start + AD_REFRESH_S)
        );

        // A re-serve's change applies at once, whatever the clock.
        *lock(&WANTED_AD) = Some(AdSpec {
            data: "1xyz".into(),
            addrs: None,
        });
        adv.tick().unwrap();
        assert_eq!(
            ad_calls().last().unwrap(),
            &(
                "discoStartAdvertising".to_string(),
                json!([RLN_GIFTER_SERVICE_ID, "1xyz", ""])
            )
        );
        lp::fake::clear();
        reset_ads();
    }

    // The owner thread re-serves while the worker is inside a libp2p call,
    // whose reply only the owner thread's event loop delivers: serve makes no
    // libp2p call and waits on nothing the worker holds; the worker places
    // the latest wish afterwards.
    #[test]
    fn a_re_serve_while_the_worker_serves_calls_no_libp2p_and_waits_for_nothing() {
        use std::sync::mpsc;
        use std::time::{Duration, Instant};
        let _g = lock(&AD_STATE);
        reset_ads();
        let spec = |data: &str| AdSpec {
            data: data.into(),
            addrs: None,
        };
        let args = json!({ "config": acct(1), "wallet": "w" }).to_string();
        let wish = spec(&service_data(&[(acct(1).as_str(), "")]).unwrap());

        // The worker holds an advertisement and is inside its
        // discoStopAdvertising call until released.
        *lock(&WANTED_AD) = Some(spec("1mid"));
        *lock(&PLACED_AD) = Some(spec("1old"));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let worker = std::thread::spawn(move || {
            lp::fake::install(Box::new(move |_, m, _| {
                if m == "discoStopAdvertising" {
                    let _ = entered_tx.send(());
                    let _ = release_rx.recv_timeout(Duration::from_secs(5));
                }
                Ok(json!(true))
            }));
            let mut adv = Advertiser {
                placed: Some(Placed {
                    spec: spec("1old"),
                    at: lp::fake::START_S,
                    peers: 1,
                }),
                peers_checked_at: lp::fake::START_S,
                last_seq_no: 0,
            };
            let placed = adv.reconcile(false, 1);
            (adv, placed)
        });
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the worker is inside its libp2p call");

        let mut state = ServeState {
            mounted: true,
            advertiser: None,
        };
        lp::fake::install(Box::new(|_, m, _| Err(format!("unscripted {m}"))));
        let t = Instant::now();
        let reply = super::serve(&mut state, &args).unwrap();
        let waited = t.elapsed();
        let _ = release_tx.send(());
        let (mut adv, placed) = worker.join().unwrap();
        assert!(
            waited < Duration::from_secs(1),
            "serve waited {waited:?} on the worker"
        );
        assert!(lp::fake::calls().is_empty(), "{:?}", lp::fake::methods());
        assert_eq!(reply["advertisePending"], json!(true));
        assert_eq!(reply["advertised"], json!(false));

        // The worker placed the wish it had read; its next tick places the
        // re-serve's.
        placed.unwrap();
        assert_eq!(*lock(&PLACED_AD), Some(spec("1mid")));
        scripted_libp2p(|| 1);
        adv.tick().unwrap();
        assert_eq!(*lock(&PLACED_AD), Some(wish));

        // A re-serve wishing for what is placed: advertised, no libp2p call.
        lp::fake::install(Box::new(|_, m, _| Err(format!("unscripted {m}"))));
        let reply = super::serve(&mut state, &args).unwrap();
        assert!(lp::fake::calls().is_empty(), "{:?}", lp::fake::methods());
        assert_eq!(reply["advertised"], json!(true));
        assert_eq!(reply.get("advertisePending"), None);

        *lock(&SERVER) = None;
        lp::fake::clear();
        reset_ads();
    }

    fn tmp(name: &str) -> String {
        let p =
            std::env::temp_dir().join(format!("rln-gifter-srv-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_file(&p);
        p.to_string_lossy().into_owned()
    }

    /// `serve` args for an allocator on registry 0x0d accepting vector `t`
    /// (verifier `verifier_module`), unadvertised, with the store at `store`.
    fn vector_serve(store: &str) -> String {
        json!({
            "config": acct(0xd),
            "wallet": "w",
            "advertise": false,
            "consumedNullifiersPath": store,
            "authVerifiers": { "t": { "module": "verifier_module" } },
        })
        .to_string()
    }

    fn vector_request(request_id: &str) -> RlnGifterRequest {
        let mut idc = vec![0xab; 32];
        idc[31] = 0x0a;
        RlnGifterRequest {
            request_id: request_id.into(),
            identity_commitment: idc,
            authentication_type: b"t".to_vec(),
            ..Default::default()
        }
    }

    fn failure_text(resp: &RlnGifterResponse) -> String {
        resp.failure
            .as_ref()
            .map(|f| f.error_message.clone())
            .or_else(|| resp.error.clone())
            .unwrap_or_default()
    }

    // The owner thread re-serves with another store file while the worker
    // waits for the verifier's verdict: the reservation the request makes
    // afterwards belongs in the new file, or a restart on it grants the
    // credential a second membership.
    #[test]
    fn a_reservation_made_after_a_re_serve_lands_in_the_new_store_file() {
        let _g = lock(&AD_STATE);
        reset_ads();
        let (old, new) = (tmp("reserve-old"), tmp("reserve-new"));
        let re_serve = vector_serve(&new);
        lp::fake::install(Box::new(move |_, method, _| match method {
            rln_auth_vector::VERIFY_METHOD => {
                let _ = serve(&re_serve);
                Ok(json!({ "ok": true, "nullifier": " AA " }))
            }
            "register_member" => Ok(json!({ "leaf_index": 3 })),
            "get_membership" => {
                Ok(json!({ "registered": true, "state": "active", "leaf_index": 3 }))
            }
            "mountProtocol" => Err("refused in test".into()),
            m => Err(format!("unscripted {m}")),
        }));
        assert_eq!(
            serve(&vector_serve(&old)).unwrap_err(),
            "mountProtocol: refused in test"
        );

        let resp = handle_request(&vector_request("r1").encode(), Some("peer"));
        assert!(resp.success.is_some(), "{}", failure_text(&resp));
        let nul = rln_auth_vector::namespaced_nullifier(&acct(0xd), "t", "aa");
        assert!(
            auth::load_nullifiers(&new).unwrap().contains(&nul),
            "the reservation is in the file serve named last"
        );
        assert!(!auth::load_nullifiers(&old).unwrap().contains(&nul));

        *lock(&SERVER) = None;
        lp::fake::clear();
        reset_ads();
        let _ = std::fs::remove_file(&old);
        let _ = std::fs::remove_file(&new);
    }

    // The re-serve lands while the registration is in flight; the
    // registration then reaches nothing on chain. The release takes the line
    // out of the file serve named last (which inherited it), so a restart on
    // that file finds the credential unspent.
    #[test]
    fn a_release_after_a_re_serve_takes_the_line_out_of_the_new_store_file() {
        let _g = lock(&AD_STATE);
        reset_ads();
        let (old, new) = (tmp("release-old"), tmp("release-new"));
        let re_serve = vector_serve(&new);
        lp::fake::install(Box::new(move |_, method, _| match method {
            rln_auth_vector::VERIFY_METHOD => Ok(json!({ "ok": true, "nullifier": "bb" })),
            "register_member" => {
                let _ = serve(&re_serve);
                Ok(json!({ "error": "full: the registry is full" }))
            }
            "mountProtocol" => Err("refused in test".into()),
            m => Err(format!("unscripted {m}")),
        }));
        assert_eq!(
            serve(&vector_serve(&old)).unwrap_err(),
            "mountProtocol: refused in test"
        );

        let refused = "not submitted: register_member refused: full: the registry is full";
        let resp = handle_request(&vector_request("r2").encode(), Some("peer"));
        assert_eq!(failure_text(&resp), refused);
        let nul = rln_auth_vector::namespaced_nullifier(&acct(0xd), "t", "bb");
        assert!(
            !auth::load_nullifiers(&new).unwrap().contains(&nul),
            "the release rewrote the file serve named last"
        );
        // Released in memory too: a retry reserves the credential again.
        let resp = handle_request(&vector_request("r3").encode(), Some("peer"));
        assert_eq!(failure_text(&resp), refused);

        *lock(&SERVER) = None;
        lp::fake::clear();
        reset_ads();
        let _ = std::fs::remove_file(&old);
        let _ = std::fs::remove_file(&new);
    }

    // `serve` names a wallet; the registration still asks the registry
    // module to pay from its own payer, the account its fee comes from.
    #[test]
    fn a_registration_is_paid_by_the_registry_modules_own_payer() {
        let _g = lock(&AD_STATE);
        reset_ads();
        let store = tmp("module-payer");
        lp::fake::install(Box::new(|_, method, _| match method {
            rln_auth_vector::VERIFY_METHOD => Ok(json!({ "ok": true, "nullifier": "ee" })),
            "register_member" => Ok(json!({ "leaf_index": 3 })),
            "get_membership" => {
                Ok(json!({ "registered": true, "state": "active", "leaf_index": 3 }))
            }
            "mountProtocol" => Err("refused in test".into()),
            m => Err(format!("unscripted {m}")),
        }));
        assert_eq!(
            serve(&vector_serve(&store)).unwrap_err(),
            "mountProtocol: refused in test"
        );

        let resp = handle_request(&vector_request("r6").encode(), Some("peer"));
        assert!(resp.success.is_some(), "{}", failure_text(&resp));
        let payers: Vec<Value> = lp::fake::calls()
            .into_iter()
            .filter(|(m, _)| m == "register_member")
            .map(|(_, mut args)| args[1].take())
            .collect();
        assert_eq!(payers, [json!("")]);

        *lock(&SERVER) = None;
        lp::fake::clear();
        reset_ads();
        let _ = std::fs::remove_file(&store);
    }

    // The registry never shows the membership: the request is answered
    // unconfirmed once the budget `serve` named has passed, not the default.
    #[test]
    fn an_unconfirmed_registration_is_answered_after_the_configured_budget() {
        let _g = lock(&AD_STATE);
        reset_ads();
        let store = tmp("confirm-budget");
        lp::fake::install(Box::new(|_, method, _| match method {
            rln_auth_vector::VERIFY_METHOD => Ok(json!({ "ok": true, "nullifier": "ff" })),
            "register_member" => Ok(json!({ "leaf_index": 3 })),
            "get_membership" => Ok(json!({ "registered": false })),
            "mountProtocol" => Err("refused in test".into()),
            m => Err(format!("unscripted {m}")),
        }));
        let args = json!({
            "config": acct(0xd),
            "advertise": false,
            "consumedNullifiersPath": store,
            "confirmBudgetSec": 7,
            "authVerifiers": { "t": { "module": "verifier_module" } },
        })
        .to_string();
        assert_eq!(serve(&args).unwrap_err(), "mountProtocol: refused in test");

        let start = lp::now_s();
        let resp = handle_request(&vector_request("r7").encode(), Some("peer"));
        assert_eq!(
            failure_text(&resp),
            "unconfirmed: registration submitted (tx ) but not on chain within 7s; it may still land"
        );
        let waited = lp::now_s() - start;
        assert!(
            (7..DEFAULT_CONFIRM_BUDGET_S).contains(&waited),
            "waited {waited}s"
        );
        // An unknown outcome keeps the credential spent.
        let nul = rln_auth_vector::namespaced_nullifier(&acct(0xd), "t", "ff");
        assert!(auth::load_nullifiers(&store).unwrap().contains(&nul));

        *lock(&SERVER) = None;
        lp::fake::clear();
        reset_ads();
        let _ = std::fs::remove_file(&store);
    }

    #[test]
    fn serve_rejects_a_confirm_budget_that_is_not_a_positive_integer() {
        for bad in [json!(0), json!("150"), json!(-5), json!(1.5)] {
            let args = json!({ "config": acct(1), "confirmBudgetSec": bad }).to_string();
            let e = serve(&args).unwrap_err();
            assert!(e.contains("confirmBudgetSec"), "{bad}: {e}");
        }
    }

    // `wallet` is optional: a serve without it gets as far as one with it.
    #[test]
    fn serve_does_not_require_a_wallet() {
        let e = serve(r#"{"config":"c"}"#).unwrap_err();
        assert!(!e.contains("wallet"), "got: {e}");
    }

    /// The protocol's error payload for a call to the registry module.
    fn lez_call_error(code: &str, message: &str) -> String {
        json!({ "code": code, "message": message, "origin": lp::LEZ_RLN_MODULE }).to_string()
    }

    const REGISTER_TIMED_OUT: &str =
        "call to 'liblogos_lez_rln_module.register_member' timed out after 190000ms";
    const LEZ_NOT_LOADED: &str = "replica for 'liblogos_lez_rln_module' is gone";

    // register_member's deadline elapses with no reply: the registry module
    // may have accepted the transaction, so the credential stays spent, in
    // the file and in memory, and the requester learns it may still land.
    #[test]
    fn a_register_member_timeout_keeps_the_reservation() {
        let _g = lock(&AD_STATE);
        reset_ads();
        let store = tmp("register-timeout");
        lp::fake::install(Box::new(|_, method, _| match method {
            rln_auth_vector::VERIFY_METHOD => Ok(json!({ "ok": true, "nullifier": "cc" })),
            "register_member" => Err(lez_call_error("timeout", REGISTER_TIMED_OUT)),
            "get_membership" => Ok(json!({ "registered": false })),
            "mountProtocol" => Err("refused in test".into()),
            m => Err(format!("unscripted {m}")),
        }));
        assert_eq!(
            serve(&vector_serve(&store)).unwrap_err(),
            "mountProtocol: refused in test"
        );

        let resp = handle_request(&vector_request("r4").encode(), Some("peer"));
        let nul = rln_auth_vector::namespaced_nullifier(&acct(0xd), "t", "cc");
        assert!(
            auth::load_nullifiers(&store).unwrap().contains(&nul),
            "the reservation stays in the store file"
        );
        assert!(resp.auth_success);
        assert_eq!(
            failure_text(&resp),
            format!(
                "{}{}; it may still land",
                crate::wire::UNCONFIRMED_PREFIX,
                lez_call_error("timeout", REGISTER_TIMED_OUT)
            )
        );
        // Kept in memory too: a retry finds the credential spent and submits
        // nothing.
        let resp = handle_request(&vector_request("r5").encode(), Some("peer"));
        assert_eq!(
            failure_text(&resp),
            format!("credential already used: {nul}")
        );
        let registers = lp::fake::methods()
            .into_iter()
            .filter(|m| m == "register_member")
            .count();
        assert_eq!(registers, 1);

        *lock(&SERVER) = None;
        lp::fake::clear();
        reset_ads();
        let _ = std::fs::remove_file(&store);
    }

    // The protocol reports that the registry module never ran
    // register_member (it is not loaded): nothing can land, so the
    // credential is released, in the file and in memory.
    #[test]
    fn a_register_member_call_the_module_never_ran_releases_the_reservation() {
        let _g = lock(&AD_STATE);
        reset_ads();
        let store = tmp("register-not-run");
        lp::fake::install(Box::new(|_, method, _| match method {
            rln_auth_vector::VERIFY_METHOD => Ok(json!({ "ok": true, "nullifier": "dd" })),
            "register_member" => Err(lez_call_error("object_unavailable", LEZ_NOT_LOADED)),
            "mountProtocol" => Err("refused in test".into()),
            m => Err(format!("unscripted {m}")),
        }));
        assert_eq!(
            serve(&vector_serve(&store)).unwrap_err(),
            "mountProtocol: refused in test"
        );

        let refused = format!(
            "{}{}",
            crate::wire::NOT_SUBMITTED_PREFIX,
            lez_call_error("object_unavailable", LEZ_NOT_LOADED)
        );
        let resp = handle_request(&vector_request("r6").encode(), Some("peer"));
        assert_eq!(failure_text(&resp), refused);
        let nul = rln_auth_vector::namespaced_nullifier(&acct(0xd), "t", "dd");
        assert!(!auth::load_nullifiers(&store).unwrap().contains(&nul));
        // Released in memory too: a retry reserves the credential again.
        let resp = handle_request(&vector_request("r7").encode(), Some("peer"));
        assert_eq!(failure_text(&resp), refused);

        *lock(&SERVER) = None;
        lp::fake::clear();
        reset_ads();
        let _ = std::fs::remove_file(&store);
    }
}
