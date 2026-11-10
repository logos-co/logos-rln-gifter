// Raw lp_* cross-module client with explicit per-call timeouts, keyed by target
// module. The SDK's PluginProxy pins timeout_ms=0 (the 20s protocol default),
// while the gifter's protocolRequest and register_member run up to ~190s — so we
// bind the consumer C ABI directly. Reply envelope matches the SDK's call_json: parse(result_json),
// which is a value object for universal C++ modules (libp2p_module) and a
// JSON-encoded string for cdylib modules (liblogos_lez_rln_module).

use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::sync::{Mutex, OnceLock};
use std::thread::ThreadId;
use std::time::Duration;

use base64::Engine;
use serde_json::Value;

// lp targets. libp2p_module IS declared in metadata.json (the one module
// this one cannot do anything without; logoscore loads it first), but it is
// still reached through this raw client for the per-call timeouts the SDK
// client does not give. The registry module and the auth vector modules are
// not declared: the per-target clients are created lazily, so a deployment
// missing one (e.g. a headless allocator without some vector's producer
// module) still loads and only fails if that target is actually called.
// Auth vector modules are named by CONFIGURATION (authProvider /
// authVerifiers), never by constants here — this module knows no vector by
// name.
// The lez module (liblogos_lez_rln_module): `register_member` lives on it.
pub const LEZ_RLN_MODULE: &str = "liblogos_lez_rln_module";
pub const LIBP2P_MODULE: &str = "libp2p_module";

/// Standard base64 (padded) — the encoding libp2p_module's stream JSON wrappers
/// use for opaque payloads on the wire.
pub fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The LIDL `bstr` wire form: `{"_bytes": "<base64url, unpadded>"}`.
pub(crate) fn bstr(bytes: &[u8]) -> Value {
    serde_json::json!({ "_bytes": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes) })
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| format!("base64 decode: {e}"))
}

#[cfg(not(test))]
mod ffi {
    use std::ffi::{c_char, c_int, c_void};

    #[repr(C)]
    pub struct LpClient {
        _private: [u8; 0],
    }

    pub type LpResultCb = extern "C" fn(ok: c_int, json: *const c_char, user_data: *mut c_void);

    extern "C" {
        pub fn lp_client_create(
            target_module: *const c_char,
            origin_module: *const c_char,
            target_transport_json: *const c_char,
            capability_transport_json: *const c_char,
        ) -> *mut LpClient;
        pub fn lp_invoke(
            client: *mut LpClient,
            method: *const c_char,
            args_json: *const c_char,
            timeout_ms: c_int,
            out_result_json: *mut *mut c_char,
            out_error_json: *mut *mut c_char,
        ) -> c_int;
        pub fn lp_invoke_async(
            client: *mut LpClient,
            method: *const c_char,
            args_json: *const c_char,
            timeout_ms: c_int,
            cb: LpResultCb,
            user_data: *mut c_void,
        ) -> c_int;
        pub fn lp_string_free(s: *mut c_char);
    }

    pub const LP_OK: c_int = 0;
}

// The unit-test binary has no protocol archive to resolve lp_* against; stub as
// "no client" so call sites compile and every path degrades to an error.
#[cfg(test)]
mod ffi {
    use std::ffi::{c_char, c_int, c_void};

    #[repr(C)]
    pub struct LpClient {
        _private: [u8; 0],
    }

    pub type LpResultCb = extern "C" fn(ok: c_int, json: *const c_char, user_data: *mut c_void);

    pub unsafe fn lp_client_create(
        _t: *const c_char,
        _o: *const c_char,
        _tt: *const c_char,
        _ct: *const c_char,
    ) -> *mut LpClient {
        std::ptr::null_mut()
    }
    pub unsafe fn lp_invoke(
        _c: *mut LpClient,
        _m: *const c_char,
        _a: *const c_char,
        _t: c_int,
        _r: *mut *mut c_char,
        _e: *mut *mut c_char,
    ) -> c_int {
        -3
    }
    pub unsafe fn lp_invoke_async(
        _c: *mut LpClient,
        _m: *const c_char,
        _a: *const c_char,
        _t: c_int,
        _cb: LpResultCb,
        _u: *mut c_void,
    ) -> c_int {
        -3
    }
    pub unsafe fn lp_string_free(_s: *mut c_char) {}

    pub const LP_OK: c_int = 0;
}

struct ClientHandle(*mut ffi::LpClient);
// SAFETY: the wrapped `lp_client*` is never destroyed (nothing in this crate
// calls `lp_client_destroy`), so it is valid for the rest of the process, and
// logos_protocol.h makes handles thread-safe per handle ("calls on one handle
// may be made from any thread"). Moving it to the serve worker is sound.
unsafe impl Send for ClientHandle {}

// OWNERSHIP: process-lifetime client table: written on the owner thread, read
// by the serve worker; a handle is never destroyed.
static CLIENTS: Mutex<Option<HashMap<String, ClientHandle>>> = Mutex::new(None);
// OWNERSHIP: set once by `init`, which the module's one-shot on_context_ready
// calls; read from every thread.
static OWNER: OnceLock<ThreadId> = OnceLock::new();

pub(crate) fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// Create a client on the owner thread (MUST run there — async replies are
// delivered from the owner's pump). Not idempotent: callers check `cached_client`
// first (a second insert would drop the first handle without destroying its client).
fn create_client(target: &str) -> bool {
    let (Ok(t), Ok(o)) = (CString::new(target), CString::new("core")) else {
        return false;
    };
    // SAFETY: `t` and `o` are NUL-terminated and outlive the call, which borrows
    // its `const char*` inputs only for its duration; NULL transports select the
    // process default. The handle is null-checked below and never destroyed.
    let raw = unsafe {
        ffi::lp_client_create(t.as_ptr(), o.as_ptr(), std::ptr::null(), std::ptr::null())
    };
    if raw.is_null() {
        eprintln!("rln_gifter: lp_client_create failed for {target}");
        return false;
    }
    lock(&CLIENTS)
        .get_or_insert_with(HashMap::new)
        .insert(target.to_string(), ClientHandle(raw));
    true
}

/// Record the owner (host Qt) thread and pre-create clients for the given
/// targets. Called from on_context_ready on the owner thread — the gifter's
/// background serve threads then reach these clients via lp_invoke_async.
pub fn init(targets: &[&str]) {
    // The generated hook fires on_context_ready once per process, so the
    // owner is recorded once.
    let _ = OWNER.set(std::thread::current().id());
    for t in targets {
        create_client(t);
    }
}

fn on_owner_thread() -> bool {
    OWNER
        .get()
        .is_some_and(|id| *id == std::thread::current().id())
}

/// Open a client for `target` while still on the owner thread, so worker
/// threads (which cannot create clients) find it ready. Errors instead of
/// deferring: a config-named module that can't be opened must fail the
/// configuring call, not every later request.
pub fn ensure_client(target: &str) -> Result<(), String> {
    // A test thread with the fake installed reaches every target through it.
    #[cfg(test)]
    if fake::installed() {
        return Ok(());
    }
    if cached_client(target).is_some() {
        return Ok(());
    }
    if !on_owner_thread() {
        return Err(format!(
            "cannot open lp client for {target} off the owner thread"
        ));
    }
    if create_client(target) {
        Ok(())
    } else {
        Err(format!(
            "lp_client_create failed for {target} (is the module loaded?)"
        ))
    }
}

/// The opened client for `target`, one lookup under one lock.
fn cached_client(target: &str) -> Option<*mut ffi::LpClient> {
    lock(&CLIENTS).as_ref()?.get(target).map(|h| h.0)
}

fn client_ptr(target: &str) -> Option<*mut ffi::LpClient> {
    if let Some(client) = cached_client(target) {
        return Some(client);
    }
    // A miss on the owner thread opens the client. `lp_client_create` is
    // host code and runs with CLIENTS unlocked, so nothing it calls back into
    // can block on the table; the table is read again once it returns.
    if on_owner_thread() {
        create_client(target);
    }
    cached_client(target)
}

struct AsyncReply {
    tx: std::sync::mpsc::Sender<(bool, String)>,
}

extern "C" fn reply_trampoline(ok: c_int, json: *const c_char, user_data: *mut c_void) {
    if user_data.is_null() {
        return;
    }
    // SAFETY: this trampoline is only passed to `lp_invoke_async` in `call_json`,
    // with `user_data` from `Box::into_raw(Box<AsyncReply>)`. The protocol calls it
    // exactly once per call that returned LP_OK and never for a refused one (which
    // `call_json` reclaims itself), and no client is ever destroyed, so this is the
    // only reclaim of a live box. `AsyncReply` holds only an `mpsc::Sender` (Send),
    // so dropping it on the protocol's thread is sound; if the caller already timed
    // out, only the `send` below fails.
    let reply = unsafe { Box::from_raw(user_data as *mut AsyncReply) };
    let raw = if json.is_null() {
        String::new()
    } else {
        // SAFETY: `json` is non-null (checked above) and, per `lp_result_cb`, a
        // NUL-terminated string valid for the duration of this callback; it is copied
        // out before the callback returns.
        unsafe { CStr::from_ptr(json) }
            .to_string_lossy()
            .into_owned()
    };
    let _ = reply.tx.send((ok != 0, raw));
}

fn err_message(raw: &str) -> String {
    serde_json::from_str::<Value>(raw)
        .ok()
        .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(String::from))
        .unwrap_or_else(|| raw.to_string())
}

fn parse_ok(raw: &str) -> Value {
    if raw.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_string()))
    }
}

/// Why a cross-module call returned no value, split by whether the target
/// may have run it.
pub(crate) enum CallError {
    /// A definite outcome: the call was refused before dispatch, the protocol
    /// reported that the target did not run it, or the target answered.
    Failed(String),
    /// No definite answer: the call may have reached the target and run (its
    /// deadline elapsed, the transport failed mid-call, the reply never came).
    Unanswered(String),
}

impl CallError {
    pub(crate) fn into_message(self) -> String {
        match self {
            CallError::Failed(m) | CallError::Unanswered(m) => m,
        }
    }
}

/// Protocol error codes after which the target did not run the call: the
/// argument checks of lp_invoke, and logos_call_error.h's unavailable target,
/// undispatchable call and rejected token. Every other code ("timeout",
/// "transport_error") leaves the outcome open. logos-protocol 0.9
/// (`callErrorFromWire`, logos_call_error.h) maps any wire code it does not
/// recognise to "call_failed", and "call_failed" is listed here because its only
/// source is a method that could not be invoked; the list therefore depends on
/// the 0.9 and later error vocabulary and must be re-checked when the protocol
/// version changes.
const NOT_RUN_CODES: [&str; 5] = [
    "invalid_arg",
    "invalid_args",
    "object_unavailable",
    "call_failed",
    "unauthorized",
];

/// The `CallError` kind for the protocol's error payload
/// `{"code","message","origin"}`; a payload without a known code is unanswered.
fn kind_of(payload: &str) -> fn(String) -> CallError {
    let not_run = serde_json::from_str::<Value>(payload).is_ok_and(|v| {
        v.get("code")
            .and_then(Value::as_str)
            .is_some_and(|code| NOT_RUN_CODES.contains(&code))
    });
    if not_run {
        CallError::Failed
    } else {
        CallError::Unanswered
    }
}

/// One cross-module call: JSON-array args in, the reply value out. On the owner
/// thread uses synchronous lp_invoke (its wait loop pumps the owner Qt loop);
/// off it uses lp_invoke_async + a channel. `timeout_ms` is the explicit
/// per-call budget.
pub fn call_json(
    target: &str,
    method: &str,
    args: &Value,
    timeout_ms: i32,
) -> Result<Value, String> {
    call_json_classified(target, method, args, timeout_ms).map_err(CallError::into_message)
}

/// `call_json`, with the failure classified by whether the target may have
/// run the call.
pub(crate) fn call_json_classified(
    target: &str,
    method: &str,
    args: &Value,
    timeout_ms: i32,
) -> Result<Value, CallError> {
    // A scripted failure stands for the protocol's error payload.
    #[cfg(test)]
    if let Some(r) = fake::intercept(target, method, args) {
        return r.map_err(|payload| kind_of(&payload)(payload));
    }
    let client = client_ptr(target)
        .ok_or_else(|| CallError::Failed(format!("no lp client for {target}")))?;
    let (Ok(method_c), Ok(args_c)) = (CString::new(method), CString::new(args.to_string())) else {
        return Err(CallError::Failed(format!(
            "{method}: args not CString-safe"
        )));
    };

    if on_owner_thread() {
        let mut result_json: *mut c_char = std::ptr::null_mut();
        let mut error_json: *mut c_char = std::ptr::null_mut();
        // SAFETY: `client` is a CLIENTS handle, never destroyed; `method_c` and `args_c`
        // are NUL-terminated and outlive the call; both out-pointers point at locals
        // initialised to null, which the library may set to strings this function then
        // owns and frees below.
        let rc = unsafe {
            ffi::lp_invoke(
                client,
                method_c.as_ptr(),
                args_c.as_ptr(),
                timeout_ms,
                &mut result_json,
                &mut error_json,
            )
        };
        if rc != ffi::LP_OK {
            if error_json.is_null() {
                return Err(CallError::Unanswered(format!("{method}: lp error {rc}")));
            }
            // SAFETY: `error_json` is non-null, NUL-terminated and owned by this function
            // until the `lp_string_free` below; it is copied out first.
            let m = unsafe { CStr::from_ptr(error_json) }
                .to_string_lossy()
                .into_owned();
            // SAFETY: `error_json` came from `lp_invoke`, is freed exactly once here and is
            // not read afterwards (`m` is an owned copy).
            unsafe { ffi::lp_string_free(error_json) };
            return Err(kind_of(&m)(m));
        }
        let raw = if result_json.is_null() {
            String::new()
        } else {
            // SAFETY: `result_json` is non-null, NUL-terminated and owned by this function
            // until the `lp_string_free` below; it is copied out first.
            let s = unsafe { CStr::from_ptr(result_json) }
                .to_string_lossy()
                .into_owned();
            // SAFETY: `result_json` came from `lp_invoke`, is freed exactly once here and
            // is not read afterwards (`s` is an owned copy).
            unsafe { ffi::lp_string_free(result_json) };
            s
        };
        return Ok(parse_ok(&raw));
    }

    let (tx, rx) = std::sync::mpsc::channel::<(bool, String)>();
    // OWNERSHIP: the reply box belongs to the host until reply_trampoline
    // reclaims it; a refused dispatch reclaims it below.
    let user_data = Box::into_raw(Box::new(AsyncReply { tx })) as *mut c_void;
    // SAFETY: `client` is a never-destroyed CLIENTS handle and `lp_invoke_async`
    // may be called from any thread; `method_c` and `args_c` are NUL-terminated and
    // outlive the call. On LP_OK `user_data` belongs to the protocol until
    // `reply_trampoline` reclaims it; otherwise it is still ours (see below).
    let rc = unsafe {
        ffi::lp_invoke_async(
            client,
            method_c.as_ptr(),
            args_c.as_ptr(),
            timeout_ms,
            reply_trampoline,
            user_data,
        )
    };
    if rc != ffi::LP_OK {
        // SAFETY: a return other than LP_OK means the call was refused before dispatch
        // and the callback is never invoked (logos_protocol.h, lp_invoke_async), so
        // `user_data` is still the box made above and nothing else frees it.
        drop(unsafe { Box::from_raw(user_data as *mut AsyncReply) });
        return Err(CallError::Failed(format!(
            "{method}: lp_invoke_async dispatch failed rc={rc}"
        )));
    }
    // The protocol owns timeout enforcement; the margin only guards a callback
    // that never fires.
    let wait = Duration::from_millis(timeout_ms as u64 + 10_000);
    let (ok, raw) = rx
        .recv_timeout(wait)
        .map_err(|_| CallError::Unanswered(format!("{method}: reply channel timed out")))?;
    if !ok {
        return Err(kind_of(&raw)(format!("{method}: {}", err_message(&raw))));
    }
    Ok(parse_ok(&raw))
}

/// Call a UNIVERSAL C++ module (libp2p_module), whose reply is a serialized
/// StdLogosResult envelope `{success, error, value}` — honor success/error and
/// return the inner `value`. Tolerates a double-encoded string envelope, and a
/// bare value for methods that don't wrap.
pub fn call_libp2p(method: &str, args: &Value, timeout_ms: i32) -> Result<Value, String> {
    let v = call_json(LIBP2P_MODULE, method, args, timeout_ms)?;
    let mut env = match v {
        Value::String(s) if !s.is_empty() => {
            serde_json::from_str(&s).map_err(|e| format!("{method}: reply parse: {e}"))?
        }
        other => other,
    };
    if env.is_object() && env.get("success").is_some() {
        let ok = env.get("success").and_then(Value::as_bool).unwrap_or(true);
        if !ok {
            let e = env
                .get("error")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .unwrap_or("libp2p call failed");
            return Err(format!("{method}: {e}"));
        }
        return Ok(env.get_mut("value").map(Value::take).unwrap_or(Value::Null));
    }
    Ok(env)
}

/// Call a cdylib module method whose reply is a QString carrying JSON (the
/// rln/membership convention): unwrap the JSON-string envelope to the inner
/// object. An empty string is the module's own failure signal.
pub fn call_module_json(
    target: &str,
    method: &str,
    args: &Value,
    timeout_ms: i32,
) -> Result<Value, String> {
    call_module_json_classified(target, method, args, timeout_ms).map_err(CallError::into_message)
}

/// `call_module_json`, with the failure classified by whether the target may
/// have run the call; a reply it cannot use is the target's answer.
pub(crate) fn call_module_json_classified(
    target: &str,
    method: &str,
    args: &Value,
    timeout_ms: i32,
) -> Result<Value, CallError> {
    let v = call_json_classified(target, method, args, timeout_ms)?;
    match v {
        Value::String(s) if !s.is_empty() => serde_json::from_str(&s)
            .map_err(|e| CallError::Failed(format!("{method}: reply parse: {e}"))),
        Value::String(_) => Err(CallError::Failed(format!("{method}: empty reply"))),
        other => Ok(other),
    }
}

/// libp2p_module's `PeerDirection` ordinal for connections this node dialled:
/// nim-libp2p's cbind declares `PeerDirection = enum Inbound, Outbound` and
/// nim-ffi emits it as a C enum numbered from 0 (`PEER_DIRECTION_OUTBOUND`).
pub(crate) const PEER_DIRECTION_OUTBOUND: i64 = 1;
/// How long a client waits for its first outbound peer, polling once a second.
/// Bootstrap peers sit unprobed in the routing table until dialled, so an
/// outbound connection is the only sign the node has joined the DHT.
pub(crate) const JOIN_WAIT_S: u64 = 20;
const PEERS_TIMEOUT_MS: i32 = 10_000;

/// How many outbound peers this node is connected to.
pub(crate) fn outbound_peers() -> Result<usize, String> {
    let v = call_libp2p(
        "connectedPeers",
        &serde_json::json!([PEER_DIRECTION_OUTBOUND]),
        PEERS_TIMEOUT_MS,
    )?;
    v.as_array()
        .map(Vec::len)
        .ok_or_else(|| format!("connectedPeers: not a peer list: {v}"))
}

/// The outbound peer count once it is at least one, or after `JOIN_WAIT_S`
/// (then 0). `Err` is a node whose libp2p cannot answer.
pub(crate) fn wait_joined() -> Result<usize, String> {
    let deadline = now_s() + JOIN_WAIT_S;
    loop {
        let n = outbound_peers()?;
        if n > 0 || now_s() >= deadline {
            return Ok(n);
        }
        sleep_s(1);
    }
}

/// Unix seconds; under test, the installed fake's virtual clock.
pub(crate) fn now_s() -> u64 {
    #[cfg(test)]
    if let Some(t) = fake::now() {
        return t;
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Sleep; under test with a fake installed, advance its clock instead.
pub(crate) fn sleep_s(s: u64) {
    #[cfg(test)]
    if fake::advance(s) {
        return;
    }
    std::thread::sleep(Duration::from_secs(s));
}

/// A scripted stand-in for every cross-module call, per test thread: a
/// thread without one installed reaches the FFI stub. Each intercepted call
/// is logged, and the clock is virtual: `sleep_s` advances it.
#[cfg(test)]
pub(crate) mod fake {
    use std::cell::RefCell;

    use serde_json::Value;

    pub(crate) type Handler = Box<dyn Fn(&str, &str, &Value) -> Result<Value, String> + Send>;

    /// The virtual clock's reading right after `install`.
    pub(crate) const START_S: u64 = 1_700_000_000;

    struct State {
        handler: Option<Handler>,
        calls: Vec<(String, Value)>,
        now: u64,
    }

    thread_local! {
        static FAKE: RefCell<Option<State>> = const { RefCell::new(None) };
    }

    pub(crate) fn install(handler: Handler) {
        FAKE.with(|f| {
            *f.borrow_mut() = Some(State {
                handler: Some(handler),
                calls: Vec::new(),
                now: START_S,
            })
        });
    }

    pub(crate) fn clear() {
        FAKE.with(|f| *f.borrow_mut() = None);
    }

    /// Every intercepted call so far, as (method, args).
    pub(crate) fn calls() -> Vec<(String, Value)> {
        FAKE.with(|f| {
            f.borrow()
                .as_ref()
                .map(|s| s.calls.clone())
                .unwrap_or_default()
        })
    }

    pub(crate) fn methods() -> Vec<String> {
        calls().into_iter().map(|(m, _)| m).collect()
    }

    pub(crate) fn installed() -> bool {
        FAKE.with(|f| f.borrow().is_some())
    }

    pub(crate) fn now() -> Option<u64> {
        FAKE.with(|f| f.borrow().as_ref().map(|s| s.now))
    }

    /// Advance the virtual clock; false when no fake is installed.
    pub(crate) fn advance(s: u64) -> bool {
        FAKE.with(|f| match f.borrow_mut().as_mut() {
            Some(st) => {
                st.now += s;
                true
            }
            None => false,
        })
    }

    pub(super) fn intercept(
        target: &str,
        method: &str,
        args: &Value,
    ) -> Option<Result<Value, String>> {
        // The handler runs outside the borrow, so it may read the clock.
        let handler = FAKE.with(|f| {
            let mut g = f.borrow_mut();
            let st = g.as_mut()?;
            st.calls.push((method.to_string(), args.clone()));
            st.handler.take()
        })?;
        let r = handler(target, method, args);
        FAKE.with(|f| {
            if let Some(st) = f.borrow_mut().as_mut() {
                st.handler = Some(handler);
            }
        });
        Some(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_failed(e: &CallError) -> bool {
        matches!(e, CallError::Failed(_))
    }

    #[test]
    fn kind_of_classifies_error_payloads() {
        let coded = |code: &str| format!(r#"{{"code":"{code}","message":"m","origin":"o"}}"#);

        for code in NOT_RUN_CODES {
            let e = kind_of(&coded(code))("x".to_string());
            assert!(is_failed(&e), "{code} must classify as Failed");
        }

        let unanswered = [
            coded("timeout"),
            coded("transport_error"),
            coded("some_future_code"),
            r#"{"message":"m","origin":"o"}"#.to_string(),
            r#"{"code":7,"message":"m"}"#.to_string(),
            "invalid_args".to_string(),
            "not json at all".to_string(),
            String::new(),
        ];
        for payload in &unanswered {
            let e = kind_of(payload)("x".to_string());
            assert!(!is_failed(&e), "{payload:?} must classify as Unanswered");
        }

        // The async path classifies the raw payload and surfaces the reformatted
        // message; the kind comes from the payload, the text from `err_message`.
        let method = "do_it";
        let raw = coded("invalid_args");
        let e = kind_of(&raw)(format!("{method}: {}", err_message(&raw)));
        assert!(is_failed(&e));
        assert_eq!(e.into_message(), "do_it: m");

        let raw = coded("timeout");
        let e = kind_of(&raw)(format!("{method}: {}", err_message(&raw)));
        assert!(!is_failed(&e));
        assert_eq!(e.into_message(), "do_it: m");

        // Classifying the reformatted message instead would lose the code.
        let reformatted = format!("{method}: {}", err_message(&coded("invalid_args")));
        assert!(!is_failed(&kind_of(&reformatted)("x".to_string())));
    }
}
