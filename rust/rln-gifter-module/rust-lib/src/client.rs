// Allocator client: request a gifted membership for an identity commitment from
// an allocator — discovered through libp2p service discovery, else the
// configured peer — over libp2p_module's generic protocolRequest bridge. The
// commitment is normally supplied by the caller (the RLN membership module,
// which keeps the identity secret). Auth is vector-agnostic: the payload is
// supplied raw or produced by an rln_auth_vector provider module named in the
// request — this module knows no vector by name.

use rln_auth_vector::ProduceRequestRef;
use serde_json::{json, Value};

use crate::lp::{self, b64, b64_decode};
use crate::wire::{
    service_data_lists, MembershipAllocationSuccess, RlnGifterRequest, RlnGifterResponse,
    RLN_GIFTER_CODEC, RLN_GIFTER_SERVICE_ID,
};

// The gifter round trip (dial + on-chain register on the server) can run up
// to ~3 minutes.
const REQUEST_TIMEOUT_MS: i64 = 190_000;
const REQUEST_CALL_TIMEOUT_MS: i32 = 205_000;
// Producer plugins may drive hardware (keycard capture covers
// connect+select+IDENTIFY plus a slow tap), so the budget is generous.
const PRODUCE_TIMEOUT_MS: i32 = 120_000;

/// How long after each of the first lookups the next one waits: discovery
/// answers from what the registrars hold, and an allocator that advertised
/// moments ago may not be placed yet. ~14 s in all.
const LOOKUP_WAITS_S: [u64; 4] = [0, 2, 4, 8];
const DISCO_TIMEOUT_MS: i32 = 30_000;

/// An allocator a discovery record names.
#[derive(Clone, Debug, PartialEq)]
pub struct Candidate {
    pub peer_id: String,
    pub addrs: Vec<String>,
}

impl Candidate {
    fn json(&self) -> Value {
        json!({ "peerId": self.peer_id, "addrs": self.addrs })
    }
}

/// The allocators in a lookup reply that advertise this (registry, auth
/// type) pair, in reply order. The reply is libp2p's record array
/// `[{peerId, addrs, services:[{id, data(base64)}]}]`.
fn candidates_in(reply: &Value, registry_hex: &str, auth_type: &str) -> Vec<Candidate> {
    let mut out = Vec::new();
    for rec in reply.as_array().map(Vec::as_slice).unwrap_or(&[]) {
        let Some(peer_id) = rec.get("peerId").and_then(Value::as_str) else {
            continue;
        };
        let listed = rec
            .get("services")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .filter(|svc| svc.get("id").and_then(Value::as_str) == Some(RLN_GIFTER_SERVICE_ID))
            .filter_map(|svc| svc.get("data").and_then(Value::as_str))
            .filter_map(|d| b64_decode(d).ok())
            .any(|data| service_data_lists(&data, registry_hex, auth_type));
        if !listed {
            continue;
        }
        let addrs: Vec<String> = rec
            .get("addrs")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        if addrs.is_empty() || out.iter().any(|c: &Candidate| c.peer_id == peer_id) {
            continue;
        }
        out.push(Candidate {
            peer_id: peer_id.to_string(),
            addrs,
        });
    }
    out
}

/// What service discovery found for a pair. `Unavailable` is a node that
/// cannot discover at all (no discovery mounted, libp2p down); `NotJoined`
/// and `NoneAdvertising` may change on a later try.
#[derive(Debug, PartialEq)]
pub(crate) enum Discovery {
    Unavailable(String),
    NotJoined,
    NoneAdvertising,
    Found(Vec<Candidate>),
}

impl Discovery {
    /// The outcome's text on the module wire (read by the membership module).
    fn message(&self, registry_hex: &str, auth_type: &str) -> String {
        match self {
            Discovery::Unavailable(e) => format!("discovery unavailable: {e}"),
            Discovery::NotJoined => format!(
                "discovery not joined: no connected peer after {}s",
                lp::JOIN_WAIT_S
            ),
            Discovery::NoneAdvertising => {
                format!("no allocator advertises {registry_hex}/{auth_type}")
            }
            Discovery::Found(_) => String::new(),
        }
    }
}

/// Look the allocators serving this pair up through libp2p service
/// discovery: register interest, wait for an outbound peer, then poll the
/// lookup until one answers or the budget ends. Also the outbound peer count
/// the join wait ended with.
fn lookup(registry_hex: &str, auth_type: &str) -> (Discovery, usize) {
    // Interest first: it builds the per-service routing table the lookups
    // query; a repeat is harmless.
    if let Err(e) = lp::call_libp2p(
        "discoRegisterInterest",
        &json!([RLN_GIFTER_SERVICE_ID]),
        DISCO_TIMEOUT_MS,
    ) {
        return (Discovery::Unavailable(e), 0);
    }
    let peers = match lp::wait_joined() {
        Ok(0) => return (Discovery::NotJoined, 0),
        Ok(n) => n,
        Err(e) => return (Discovery::Unavailable(e), 0),
    };
    for wait in LOOKUP_WAITS_S {
        if wait > 0 {
            lp::sleep_s(wait);
        }
        let reply = match lp::call_libp2p(
            "discoLookup",
            &json!([RLN_GIFTER_SERVICE_ID, ""]),
            DISCO_TIMEOUT_MS,
        ) {
            Ok(r) => r,
            Err(e) => return (Discovery::Unavailable(e), peers),
        };
        let found = candidates_in(&reply, registry_hex, auth_type);
        if !found.is_empty() {
            return (Discovery::Found(found), peers);
        }
    }
    (Discovery::NoneAdvertising, peers)
}

/// The trait's `discover`: args `{config, authType?}` → the allocators
/// currently advertising that (registry, auth type) pair,
/// `{serviceId, candidates:[{peerId, addrs}], joined, peers}`; `config` names
/// the registry (the advertisement digests are per registry), `authType`
/// absent means an open allocator. `joined` is whether an outbound peer
/// connected within the join wait, `peers` how many. A node that cannot
/// discover is an error, `discovery unavailable: <why>`.
pub fn discover(args_json: &str) -> Result<Value, String> {
    let a: Value = serde_json::from_str(args_json).map_err(|e| format!("discover args: {e}"))?;
    let registry = a
        .get("config")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or("discover needs config (the registry)")?;
    let registry = crate::wire::canonical_account(registry)?;
    let auth_type = a.get("authType").and_then(Value::as_str).unwrap_or("");
    let (outcome, peers) = lookup(&registry, auth_type);
    let candidates = match &outcome {
        Discovery::Unavailable(_) => return Err(outcome.message(&registry, auth_type)),
        Discovery::Found(c) => c.iter().map(Candidate::json).collect::<Vec<_>>(),
        Discovery::NotJoined | Discovery::NoneAdvertising => Vec::new(),
    };
    Ok(json!({
        "serviceId": RLN_GIFTER_SERVICE_ID,
        "candidates": candidates,
        "joined": outcome != Discovery::NotJoined,
        "peers": peers,
    }))
}

/// A failed `request`: the error text and, when an allocator's own reply
/// ended it, that allocator and whether discovery found it. `unconfirmed`
/// says that reply was `unconfirmed: …`: the allocator submitted the
/// registration and did not see it land in time, so it may still land.
#[derive(Debug)]
pub(crate) struct Failure {
    pub(crate) error: String,
    pub(crate) gifter: Option<(String, bool)>,
    pub(crate) unconfirmed: bool,
}

impl Failure {
    pub(crate) fn json(&self) -> Value {
        let mut out = json!({ "error": self.error });
        if let Some((peer, discovered)) = &self.gifter {
            out["gifterPeerId"] = json!(peer);
            out["discovered"] = json!(discovered);
        }
        if self.unconfirmed {
            out["unconfirmed"] = json!(true);
        }
        out
    }
}

impl From<String> for Failure {
    fn from(error: String) -> Self {
        Failure {
            error,
            gifter: None,
            unconfirmed: false,
        }
    }
}

impl From<&str> for Failure {
    fn from(error: &str) -> Self {
        Failure {
            error: error.to_string(),
            gifter: None,
            unconfirmed: false,
        }
    }
}

/// Why one allocator did not grant: before it read the request (another
/// may), or after (the registration may have happened; stop).
enum Attempt {
    Next(String),
    Stop(String),
}

impl Attempt {
    fn message(self) -> String {
        match self {
            Attempt::Next(m) | Attempt::Stop(m) => m,
        }
    }

    /// The allocator answered that it submitted the registration and did not
    /// see it land within its budget.
    fn unconfirmed(&self) -> bool {
        matches!(self, Attempt::Stop(m) if m.starts_with(crate::wire::UNCONFIRMED_PREFIX))
    }
}

/// One request→response with one allocator over the generic libp2p bridge,
/// to the caller's grant shape; a failure says whether the allocator's own
/// reply gave it. `request_b64` is `req` encoded, once for every allocator.
fn ask<A: AsRef<str>>(
    peer_id: &str,
    addrs: &[A],
    req: &RlnGifterRequest,
    request_b64: &str,
) -> Result<Value, (Attempt, bool)> {
    let unreplied = |a: Attempt| (a, false);
    // `multiaddrs` is filled straight from the caller's slice, without an intermediate Vec.
    let mut pr_args = json!({
        "peerId": peer_id,
        "multiaddrs": null,
        "proto": RLN_GIFTER_CODEC,
        "requestB64": request_b64,
        "timeoutMs": REQUEST_TIMEOUT_MS,
    });
    pr_args["multiaddrs"] = addrs.iter().map(|a| a.as_ref()).collect();
    let pr = match lp::call_libp2p(
        "protocolRequest",
        &json!([pr_args.to_string()]),
        REQUEST_CALL_TIMEOUT_MS,
    ) {
        Ok(v) => v,
        // Nothing reached the allocator: the dial or the write failed.
        Err(e)
            if e.contains("dial failed")
                || e.contains("dial returned no stream")
                || e.contains("write failed") =>
        {
            return Err(unreplied(Attempt::Next(e)))
        }
        Err(e) => return Err(unreplied(Attempt::Stop(e))),
    };
    let resp_b64 = pr
        .get("responseB64")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            unreplied(Attempt::Stop(format!(
                "protocolRequest: no responseB64 in {pr}"
            )))
        })?;
    let resp =
        RlnGifterResponse::decode(&b64_decode(resp_b64).map_err(|e| unreplied(Attempt::Stop(e)))?)
            .map_err(|e| unreplied(Attempt::Stop(e)))?;

    if resp.request_id != req.request_id {
        return Err(unreplied(Attempt::Stop(
            "gifter response requestId mismatch".into(),
        )));
    }
    judge(resp, req.config_account_id.as_deref())
        .map(|success| grant_json(peer_id, &req.identity_commitment, success))
        .map_err(|a| (a, true))
}

/// The grant, or why not and whether another allocator may be asked: a
/// refusal before registration (`auth_success` false: registry not served,
/// unsupported or rejected vector, spent credential) and a registration the
/// allocator never submitted (`not submitted: …`) move on; anything after
/// the request was acted on stops.
fn judge(
    resp: RlnGifterResponse,
    config: Option<&str>,
) -> Result<MembershipAllocationSuccess, Attempt> {
    if !resp.auth_success {
        return Err(Attempt::Next(
            resp.error
                .or_else(|| resp.failure.map(|f| f.error_message))
                .unwrap_or_else(|| "gifter authentication failed".into()),
        ));
    }
    let success = resp.success.ok_or_else(|| {
        let why = resp
            .failure
            .map(|f| f.error_message)
            .or(resp.error)
            .unwrap_or_else(|| "gifter returned no membership".into());
        if why.starts_with(crate::wire::NOT_SUBMITTED_PREFIX) {
            Attempt::Next(why)
        } else {
            Attempt::Stop(why)
        }
    })?;

    // The membership is only useful on the registry the caller polls; a
    // allocator that registered it elsewhere has spent for nothing.
    if let (Some(want), Some(got)) = (config, &success.config_account_id) {
        if !got.eq_ignore_ascii_case(want) {
            return Err(Attempt::Stop(format!(
                "gifter registered on {got}, not the requested {want}"
            )));
        }
    }
    Ok(success)
}

/// The caller's grant shape.
fn grant_json(
    peer_id: &str,
    identity_commitment: &[u8],
    success: MembershipAllocationSuccess,
) -> Value {
    let tx_hash = hex::encode(&success.transaction_hash);
    // The gifter membership flow sends no mix-RLN messages, so there is no
    // identity to adopt into a mix/proof subsystem, and the client runs against a
    // PLAIN libp2p node (vanilla upstream) that has no such surface. The app
    // persists the credential to its keystore from its own generate_identity.
    let mut out = json!({
        "leaf_index": success.leaf_index,
        "id_commitment": hex::encode(identity_commitment),
        "auth_success": true,
        "identity_adopted": false,
        "gifterPeerId": peer_id,
    });
    if !tx_hash.is_empty() {
        out["tx_hash"] = json!(tx_hash);
    }
    if let Some(cfg) = success.config_account_id {
        out["config_account"] = json!(cfg);
    }
    out
}

/// Client entry point (the trait's `request`): args
/// `{config?, identityCommitment, rate?, authType?, authPayload?,
///  authProvider?, authArgs?, discover?, gifterPeerId?, gifterMultiaddr?}`.
/// `config` names the registry (ConfigState account) the membership is
/// wanted on; absent, the allocator's default registry. Allocators advertising
/// the (registry, auth type) pair are discovered first (`discover`, default
/// true; needs `config`) and tried in turn while none has read the request;
/// the configured `gifterPeerId`+`gifterMultiaddr` pair comes after them.
/// A grant on another registry is an error.
/// Returns `{leaf_index, id_commitment, auth_success, identity_adopted,
///  gifterPeerId, discovered, tx_hash?, config_account?}`. A failure whose
/// last allocator tried answered the request itself (a refusal, a
/// registration not submitted or unconfirmed) names it: `gifterPeerId` and
/// `discovered` ride along with the error text.
pub fn request(args_json: &str) -> Result<Value, Failure> {
    let a: Value = serde_json::from_str(args_json).map_err(|e| format!("request args: {e}"))?;
    let gifter_peer_id = a
        .get("gifterPeerId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let gifter_multiaddr = a
        .get("gifterMultiaddr")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let configured = match (gifter_peer_id, gifter_multiaddr) {
        (Some(p), Some(m)) => Some((p, m)),
        (None, None) => None,
        _ => return Err("gifterPeerId and gifterMultiaddr go together".into()),
    };
    let discover = match a.get("discover") {
        None | Some(Value::Null) => true,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err("discover must be a boolean".into()),
    };
    if !discover && configured.is_none() {
        return Err("request needs discover or gifterPeerId+gifterMultiaddr".into());
    }
    let config = match a
        .get("config")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(c) => Some(crate::wire::canonical_account(c)?),
        None => None,
    };
    if discover && config.is_none() && configured.is_none() {
        return Err("discovery needs config (the registry); name one or configure gifterPeerId+gifterMultiaddr".into());
    }
    let provided_commitment = a
        .get("identityCommitment")
        .and_then(Value::as_str)
        .unwrap_or("");
    let rate = a.get("rate").and_then(Value::as_u64).unwrap_or(0);

    // The commitment comes from the caller — the RLN membership module
    // generates the credential in-module and passes only its commitment, so
    // the identity secret never reaches this module. Lowercased so producer
    // and verifier see the same string for the same commitment (the server
    // side hex-encodes, which is lowercase).
    if provided_commitment.is_empty() {
        return Err("request needs identityCommitment".into());
    }
    let id_commitment_hex = provided_commitment.trim_start_matches("0x").to_lowercase();
    let id_commitment =
        hex::decode(&id_commitment_hex).map_err(|e| format!("id_commitment hex: {e}"))?;
    // The allocator refuses the same values; failing here costs no producer
    // call, no dial and no verifier round-trip on the allocator.
    if let Some(why) = crate::wire::commitment_refusal(&id_commitment) {
        return Err(why.into());
    }
    let request_id = format!(
        "gift-{}",
        &id_commitment_hex[..id_commitment_hex.len().min(16)]
    );

    // Auth vector + payload. `authType` names the vector in the wire's
    //    OPEN authentication_type vocabulary — any type the target allocator is
    //    configured to verify (its authVerifiers modules); this client never
    //    gatekeeps it and knows no vector by name. The payload comes from
    //    `authPayload` (raw hex, verbatim — material the application produced
    //    itself, e.g. an external wallet signature) or from an `authProvider`
    //    module implementing the rln_auth_vector producer contract
    //    (PRODUCE_METHOD, `authArgs` forwarded verbatim — e.g. keycard
    //    capture). No authType at all is an UNAUTHENTICATED request for an
    //    open allocator: empty type, empty payload.
    let auth_type_req = a.get("authType").and_then(Value::as_str).unwrap_or("");
    let auth_payload_hex = a.get("authPayload").and_then(Value::as_str).unwrap_or("");
    let auth_provider = a.get("authProvider").and_then(Value::as_str).unwrap_or("");
    if !auth_payload_hex.is_empty() && !auth_provider.is_empty() {
        return Err("authPayload and authProvider are mutually exclusive".into());
    }
    let auth_payload: Vec<u8> = if auth_type_req.is_empty() {
        if !auth_payload_hex.is_empty() || !auth_provider.is_empty() {
            return Err("authPayload/authProvider need an explicit authType".into());
        }
        Vec::new()
    } else if !auth_payload_hex.is_empty() {
        hex::decode(auth_payload_hex.trim_start_matches("0x"))
            .map_err(|e| format!("authPayload hex: {e}"))?
    } else if !auth_provider.is_empty() {
        let prod_req = ProduceRequestRef {
            auth_type: auth_type_req,
            id_commitment_hex: &id_commitment_hex,
            args: a.get("authArgs"),
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
        return Err(format!("authType '{auth_type_req}' needs authPayload or authProvider").into());
    };

    let req = RlnGifterRequest {
        request_id,
        authentication_type: auth_type_req.as_bytes().to_vec(),
        authentication_payload: auth_payload,
        identity_commitment: id_commitment,
        rate_limit: if rate > 0 { Some(rate) } else { None },
        config_account_id: config,
    };
    let request_b64 = b64(&req.encode());

    // Discovered allocators first, rotated by the commitment so clients
    // spread over them; then the configured one. `last_reply` is the last
    // allocator tried when its own reply refused.
    let mut tried: Vec<String> = Vec::new();
    let mut last_reply: Option<(String, bool)> = None;
    if let (true, Some(registry)) = (discover, req.config_account_id.as_deref()) {
        match lookup(registry, auth_type_req).0 {
            Discovery::Found(mut found) => {
                let at = req.identity_commitment[0] as usize % found.len();
                found.rotate_left(at);
                for c in found {
                    match ask(&c.peer_id, &c.addrs, &req, &request_b64) {
                        Ok(mut out) => {
                            out["discovered"] = json!(true);
                            return Ok(out);
                        }
                        Err((Attempt::Next(e), replied)) => {
                            tried.push(format!("{}: {e}", c.peer_id));
                            last_reply = replied.then_some((c.peer_id, true));
                        }
                        Err((stop, replied)) => {
                            let unconfirmed = replied && stop.unconfirmed();
                            return Err(Failure {
                                error: format!("{}: {}", c.peer_id, stop.message()),
                                gifter: replied.then_some((c.peer_id, true)),
                                unconfirmed,
                            });
                        }
                    }
                }
            }
            outcome => tried.push(outcome.message(registry, auth_type_req)),
        }
    }
    if let Some((peer_id, multiaddr)) = configured {
        return match ask(peer_id, &[multiaddr], &req, &request_b64) {
            Ok(mut out) => {
                out["discovered"] = json!(false);
                Ok(out)
            }
            Err((e, replied)) => {
                let unconfirmed = replied && e.unconfirmed();
                Err(Failure {
                    error: if tried.is_empty() {
                        e.message()
                    } else {
                        format!("{}; before that: {}", e.message(), tried.join("; "))
                    },
                    gifter: replied.then(|| (peer_id.to_owned(), false)),
                    unconfirmed,
                })
            }
        };
    }
    Err(Failure {
        error: format!(
            "no allocator granted and none is configured: {}",
            tried.join("; ")
        ),
        gifter: last_reply,
        unconfirmed: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // The error text alone; the tests of the structured failure call
    // `super::request`.
    fn request(args_json: &str) -> Result<Value, String> {
        super::request(args_json).map_err(|f| f.error)
    }

    fn req(extra: &str) -> Result<Value, String> {
        request(&format!(
            r#"{{"gifterPeerId":"12D3KooWTest","gifterMultiaddr":"/ip4/127.0.0.1/tcp/1",
                 "identityCommitment":"{}",{extra}"rate":100}}"#,
            canonical()
        ))
    }

    // 0xab repeated reads (little-endian) above r; a 0x0a top byte keeps the
    // value canonical whatever the lower bytes hold.
    fn canonical() -> String {
        format!("{}0a", "ab".repeat(31))
    }
    fn canonical_upper() -> String {
        format!("{}0A", "AB".repeat(31))
    }

    #[test]
    fn non_canonical_commitment_is_refused_before_any_io() {
        for (idc, want) in [
            ("ff".repeat(32), "invalid_commitment: not a BN254"),
            ("00".repeat(32), "invalid_commitment: zero"),
            ("ab".repeat(31), "32 bytes"),
        ] {
            let e = request(&format!(
                r#"{{"gifterPeerId":"p","gifterMultiaddr":"/m","identityCommitment":"{idc}","rate":100}}"#
            ))
            .unwrap_err();
            assert!(e.contains(want), "{idc}: got {e}");
        }
    }

    #[test]
    fn a_malformed_config_account_is_refused_before_any_io() {
        let e = req(r#""config":"nope","#).unwrap_err();
        assert!(e.contains("config account 'nope'"), "got: {e}");
    }

    #[test]
    fn payload_and_provider_are_mutually_exclusive() {
        let e =
            req(r#""authType":"voucher-v1","authPayload":"aa","authProvider":"m","#).unwrap_err();
        assert!(e.contains("mutually exclusive"), "got: {e}");
    }

    #[test]
    fn payload_material_needs_an_explicit_auth_type() {
        for extra in [r#""authPayload":"aa","#, r#""authProvider":"m","#] {
            let e = req(extra).unwrap_err();
            assert!(e.contains("need an explicit authType"), "got: {e}");
        }
    }

    #[test]
    fn named_vector_needs_a_payload_source() {
        let e = req(r#""authType":"voucher-v1","#).unwrap_err();
        assert!(e.contains("needs authPayload or authProvider"), "got: {e}");
    }

    #[test]
    fn bad_payload_hex_is_rejected_before_any_io() {
        let e = req(r#""authType":"voucher-v1","authPayload":"zz","#).unwrap_err();
        assert!(e.contains("authPayload hex"), "got: {e}");
    }

    #[test]
    fn a_configured_pair_is_both_or_neither() {
        let e = request(&format!(
            r#"{{"gifterPeerId":"p","identityCommitment":"{}","rate":100}}"#,
            canonical()
        ))
        .unwrap_err();
        assert!(e.contains("go together"), "got: {e}");
    }

    #[test]
    fn without_discovery_a_pair_is_required() {
        let e = request(&format!(
            r#"{{"discover":false,"identityCommitment":"{}","rate":100}}"#,
            canonical()
        ))
        .unwrap_err();
        assert!(e.contains("needs discover or gifterPeerId"), "got: {e}");
        let e = request(&format!(
            r#"{{"discover":"no","identityCommitment":"{}"}}"#,
            canonical()
        ))
        .unwrap_err();
        assert!(e.contains("discover must be a boolean"), "got: {e}");
    }

    #[test]
    fn discovery_needs_a_registry_to_match_on() {
        let e = request(&format!(
            r#"{{"identityCommitment":"{}","rate":100}}"#,
            canonical()
        ))
        .unwrap_err();
        assert!(e.contains("discovery needs config"), "got: {e}");
        let e = discover("{}").unwrap_err();
        assert!(e.contains("discover needs config"), "got: {e}");
        let e = discover(r#"{"config":"nope"}"#).unwrap_err();
        assert!(e.contains("config account 'nope'"), "got: {e}");
    }

    #[test]
    fn a_lookup_reply_yields_the_allocators_advertising_the_pair() {
        let (d, m) = (hex::encode([0xd; 32]), hex::encode([0xa; 32]));
        let data = crate::wire::service_data(&[(d.as_str(), "peer-any")]).unwrap();
        let rec = |peer: &str, data: &str, addrs: Value| {
            json!({ "peerId": peer, "seqNo": 1, "addrs": addrs,
                    "services": [{ "id": RLN_GIFTER_SERVICE_ID, "data": b64(data.as_bytes()) }] })
        };
        let reply = json!([
            rec("A", &data, json!(["/ip4/127.0.0.1/tcp/1"])),
            rec("B", &data, json!([])),
            rec("A", &data, json!(["/ip4/127.0.0.1/tcp/2"])),
            rec("C", "1zzzz", json!(["/ip4/127.0.0.1/tcp/3"])),
            json!({ "peerId": "D", "addrs": ["/ip4/127.0.0.1/tcp/4"],
                    "services": [{ "id": "/other", "data": b64(data.as_bytes()) }] }),
        ]);
        assert_eq!(
            candidates_in(&reply, &d, "peer-any"),
            [Candidate {
                peer_id: "A".into(),
                addrs: vec!["/ip4/127.0.0.1/tcp/1".into()]
            }]
        );
        assert!(candidates_in(&reply, &m, "peer-any").is_empty());
        assert!(candidates_in(&reply, &d, "eth-allowlist").is_empty());
        assert!(candidates_in(&json!([]), &d, "peer-any").is_empty());
        assert!(candidates_in(&json!(null), &d, "peer-any").is_empty());
    }

    // Which replies let the client ask the next allocator: refusals before
    // registration and registrations the allocator never submitted; a
    // registration that may have landed, or landed elsewhere, stops.
    #[test]
    fn a_reply_says_whether_the_next_allocator_may_be_asked() {
        use crate::wire::{MembershipAllocationFailure, MembershipAllocationSuccess};
        let refused = RlnGifterResponse {
            request_id: "r".into(),
            auth_success: false,
            error: Some("credential already used: x".into()),
            ..Default::default()
        };
        assert!(
            matches!(judge(refused, None), Err(Attempt::Next(m)) if m.contains("already used"))
        );
        let not_submitted = RlnGifterResponse {
            request_id: "r".into(),
            auth_success: true,
            failure: Some(MembershipAllocationFailure {
                error_message: "not submitted: register_member refused: insufficient_balance"
                    .into(),
            }),
            ..Default::default()
        };
        assert!(
            matches!(judge(not_submitted, None), Err(Attempt::Next(m)) if m.starts_with("not submitted"))
        );
        let unconfirmed = RlnGifterResponse {
            request_id: "r".into(),
            auth_success: true,
            failure: Some(MembershipAllocationFailure {
                error_message:
                    "unconfirmed: registration submitted (tx ab) but not on chain within 150s"
                        .into(),
            }),
            ..Default::default()
        };
        assert!(
            matches!(judge(unconfirmed, None), Err(Attempt::Stop(m)) if m.starts_with("unconfirmed"))
        );
        let elsewhere = RlnGifterResponse {
            request_id: "r".into(),
            auth_success: true,
            success: Some(MembershipAllocationSuccess {
                leaf_index: 1,
                config_account_id: Some("bb".repeat(32)),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(
            matches!(judge(elsewhere, Some(&"aa".repeat(32))), Err(Attempt::Stop(m)) if m.contains("registered on"))
        );
        let granted = RlnGifterResponse {
            request_id: "r".into(),
            auth_success: true,
            success: Some(MembershipAllocationSuccess {
                leaf_index: 4,
                config_account_id: Some("aa".repeat(32)),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            judge(granted, Some(&"aa".repeat(32)))
                .map(|s| s.leaf_index)
                .ok(),
            Some(4)
        );
    }

    #[test]
    fn commitment_is_lowercased_for_the_producer_contract() {
        // Uppercase commitment + provider: fails at the lp stub, but the arg
        // shape is accepted — the identity path must not be the error.
        let e = request(&format!(
            r#"{{"gifterPeerId":"p","gifterMultiaddr":"/m",
                 "identityCommitment":"{}","authType":"t","authProvider":"m"}}"#,
            canonical_upper()
        ))
        .unwrap_err();
        assert!(!e.contains("id_commitment hex"), "got: {e}");
    }

    type Script = fn(&str, &Value) -> Option<Result<Value, String>>;

    /// A libp2p with discovery mounted, `peers` outbound peers, the lookup
    /// reply `records`, and `extra` answering anything else first.
    fn scripted(peers: usize, records: Value, extra: Script) {
        lp::fake::install(Box::new(move |_, method, args| {
            if let Some(r) = extra(method, args) {
                return r;
            }
            match method {
                "discoRegisterInterest" => Ok(json!(true)),
                "connectedPeers" => Ok(json!((0..peers)
                    .map(|i| format!("P{i}"))
                    .collect::<Vec<_>>())),
                "discoLookup" => Ok(records.clone()),
                m => Err(format!("unscripted {m}")),
            }
        }));
    }

    fn no_extra(_: &str, _: &Value) -> Option<Result<Value, String>> {
        None
    }

    fn registry() -> String {
        hex::encode([0xd; 32])
    }

    fn advertising(peer: &str, auth_type: &str) -> Value {
        let data = crate::wire::service_data(&[(registry().as_str(), auth_type)]).unwrap();
        json!([{ "peerId": peer, "seqNo": 1, "addrs": ["/ip4/127.0.0.1/tcp/1"],
                 "services": [{ "id": RLN_GIFTER_SERVICE_ID, "data": b64(data.as_bytes()) }] }])
    }

    #[test]
    fn a_lookup_says_why_it_found_nobody() {
        let (r, t) = (registry(), "peer-any");

        lp::fake::install(Box::new(|_, m, _| {
            Err(format!("{m}: service discovery not mounted"))
        }));
        let (d, _) = lookup(&r, t);
        assert_eq!(
            d.message(&r, t),
            "discovery unavailable: discoRegisterInterest: service discovery not mounted"
        );

        scripted(0, json!([]), no_extra);
        assert_eq!(lookup(&r, t), (Discovery::NotJoined, 0));
        assert_eq!(
            Discovery::NotJoined.message(&r, t),
            "discovery not joined: no connected peer after 20s"
        );
        assert_eq!(lp::now_s(), lp::fake::START_S + lp::JOIN_WAIT_S);
        assert!(!lp::fake::methods().iter().any(|m| m == "discoLookup"));

        scripted(2, json!([]), no_extra);
        assert_eq!(lookup(&r, t), (Discovery::NoneAdvertising, 2));
        assert_eq!(
            Discovery::NoneAdvertising.message(&r, t),
            format!("no allocator advertises {r}/peer-any")
        );
        assert_eq!(
            lp::fake::methods()
                .iter()
                .filter(|m| *m == "discoLookup")
                .count(),
            LOOKUP_WAITS_S.len()
        );
        assert_eq!(
            lp::now_s(),
            lp::fake::START_S + LOOKUP_WAITS_S.iter().sum::<u64>()
        );

        scripted(1, advertising("A", t), no_extra);
        assert_eq!(
            lookup(&r, t),
            (
                Discovery::Found(vec![Candidate {
                    peer_id: "A".into(),
                    addrs: vec!["/ip4/127.0.0.1/tcp/1".into()]
                }]),
                1
            )
        );
        assert_eq!(
            lp::fake::calls()[1],
            (
                "connectedPeers".to_string(),
                json!([lp::PEER_DIRECTION_OUTBOUND])
            )
        );

        scripted(0, json!([]), no_extra);
        assert_eq!(
            discover(&format!(r#"{{"config":"{r}"}}"#)).unwrap(),
            json!({ "serviceId": RLN_GIFTER_SERVICE_ID, "candidates": [], "joined": false, "peers": 0 })
        );
        lp::fake::install(Box::new(|_, m, _| Err(format!("{m}: libp2p down"))));
        assert_eq!(
            discover(&format!(r#"{{"config":"{r}"}}"#)).unwrap_err(),
            "discovery unavailable: discoRegisterInterest: libp2p down"
        );
        lp::fake::clear();
    }

    #[test]
    fn a_request_on_an_unjoined_node_says_so() {
        scripted(0, json!([]), no_extra);
        let f = super::request(&format!(
            r#"{{"config":"{}","identityCommitment":"{}"}}"#,
            registry(),
            canonical()
        ))
        .unwrap_err();
        assert_eq!(f.error, "no allocator granted and none is configured: discovery not joined: no connected peer after 20s");
        assert_eq!(f.json(), json!({ "error": f.error }));
        lp::fake::clear();
    }

    fn refusing(method: &str, _: &Value) -> Option<Result<Value, String>> {
        (method == "protocolRequest").then(|| {
            let id = format!("gift-{}", &canonical()[..16]);
            let resp = RlnGifterResponse {
                request_id: id,
                auth_success: false,
                error: Some("credential already used: x".into()),
                ..Default::default()
            };
            Ok(json!({ "responseB64": b64(&resp.encode()) }))
        })
    }

    fn unconfirmed(method: &str, _: &Value) -> Option<Result<Value, String>> {
        (method == "protocolRequest").then(|| {
            let id = format!("gift-{}", &canonical()[..16]);
            let resp = RlnGifterResponse {
                request_id: id,
                auth_success: true,
                failure: Some(crate::wire::MembershipAllocationFailure {
                    error_message: "unconfirmed: not on chain".into(),
                }),
                ..Default::default()
            };
            Ok(json!({ "responseB64": b64(&resp.encode()) }))
        })
    }

    fn undialable(method: &str, _: &Value) -> Option<Result<Value, String>> {
        (method == "protocolRequest").then(|| Err("protocolRequest: dial failed".into()))
    }

    #[test]
    fn a_failure_an_allocator_answered_names_it() {
        let args = format!(
            r#"{{"config":"{}","identityCommitment":"{}"}}"#,
            registry(),
            canonical()
        );

        scripted(1, advertising("A", ""), refusing);
        let f = super::request(&args).unwrap_err();
        assert_eq!(
            f.error,
            "no allocator granted and none is configured: A: credential already used: x"
        );
        assert_eq!(
            f.json(),
            json!({ "error": f.error, "gifterPeerId": "A", "discovered": true })
        );

        scripted(1, advertising("A", ""), unconfirmed);
        let f = super::request(&args).unwrap_err();
        assert_eq!(
            f.json(),
            json!({ "error": "A: unconfirmed: not on chain", "gifterPeerId": "A", "discovered": true, "unconfirmed": true })
        );

        let pair = format!(
            r#"{{"discover":false,"gifterPeerId":"G","gifterMultiaddr":"/m","identityCommitment":"{}"}}"#,
            canonical()
        );
        scripted(1, json!([]), unconfirmed);
        let f = super::request(&pair).unwrap_err();
        assert_eq!(
            f.json(),
            json!({ "error": "unconfirmed: not on chain", "gifterPeerId": "G", "discovered": false, "unconfirmed": true })
        );

        // Nobody read the request: no allocator to name.
        scripted(1, advertising("A", ""), undialable);
        let f = super::request(&args).unwrap_err();
        assert_eq!(
            f.json(),
            json!({ "error": "no allocator granted and none is configured: A: protocolRequest: dial failed" })
        );
        scripted(1, json!([]), undialable);
        let f = super::request(&pair).unwrap_err();
        assert_eq!(f.json(), json!({ "error": "protocolRequest: dial failed" }));
        lp::fake::clear();
    }
}
