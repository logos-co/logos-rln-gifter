// Raw lp_* cross-module client with explicit per-call timeouts, keyed by target
// module. The SDK's PluginProxy pins timeout_ms=0 (the 20s protocol default),
// while the gifter's protocolRequest and register_member run up to ~190s — so we
// bind the consumer C ABI directly, exactly as the sibling rln/membership
// modules do. Reply envelope matches the SDK's call_json: parse(result_json),
// which is a value object for universal C++ modules (libp2p_module) and a
// JSON-encoded string for cdylib modules (liblogos_rln_module).
// FEATURE: RLN membership gifter cross-module transport

use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::sync::Mutex;
use std::thread::ThreadId;
use std::time::Duration;

use base64::Engine;
use serde_json::Value;

pub const RLN_MODULE: &str = "liblogos_rln_module";
pub const LIBP2P_MODULE: &str = "libp2p_module";

/// Standard base64 (padded) — the encoding libp2p_module's stream JSON wrappers
/// use for opaque payloads on the wire.
pub fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
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
// Used per the owner-thread contract; the handle itself is read from any thread.
unsafe impl Send for ClientHandle {}

static CLIENTS: Mutex<Option<HashMap<String, ClientHandle>>> = Mutex::new(None);
static OWNER: Mutex<Option<ThreadId>> = Mutex::new(None);

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// Create a client on the owner thread (MUST run there — async replies are
// delivered from the owner's pump). Idempotent per target.
fn create_client(target: &str) -> bool {
    let (Ok(t), Ok(o)) = (CString::new(target), CString::new("core")) else {
        return false;
    };
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
    *lock(&OWNER) = Some(std::thread::current().id());
    for t in targets {
        create_client(t);
    }
}

fn on_owner_thread() -> bool {
    lock(&OWNER)
        .map(|id| id == std::thread::current().id())
        .unwrap_or(false)
}

fn client_ptr(target: &str) -> Option<*mut ffi::LpClient> {
    let have = lock(&CLIENTS)
        .as_ref()
        .map(|m| m.contains_key(target))
        .unwrap_or(false);
    if !have && on_owner_thread() {
        create_client(target);
    }
    lock(&CLIENTS)
        .as_ref()
        .and_then(|m| m.get(target))
        .map(|h| h.0)
}

struct AsyncReply {
    tx: std::sync::mpsc::Sender<(bool, String)>,
}

extern "C" fn reply_trampoline(ok: c_int, json: *const c_char, user_data: *mut c_void) {
    if user_data.is_null() {
        return;
    }
    let reply = unsafe { Box::from_raw(user_data as *mut AsyncReply) };
    let raw = if json.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(json) }.to_string_lossy().into_owned()
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

/// One cross-module call: JSON-array args in, the reply value out. On the owner
/// thread uses synchronous lp_invoke (its wait loop pumps the owner Qt loop);
/// off it uses lp_invoke_async + a channel. `timeout_ms` is the explicit
/// per-call budget.
pub fn call_json(target: &str, method: &str, args: &Value, timeout_ms: i32) -> Result<Value, String> {
    let client = client_ptr(target).ok_or_else(|| format!("no lp client for {target}"))?;
    let (Ok(method_c), Ok(args_c)) = (CString::new(method), CString::new(args.to_string())) else {
        return Err(format!("{method}: args not CString-safe"));
    };

    if on_owner_thread() {
        let mut result_json: *mut c_char = std::ptr::null_mut();
        let mut error_json: *mut c_char = std::ptr::null_mut();
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
            let msg = if error_json.is_null() {
                format!("{method}: lp error {rc}")
            } else {
                let m = unsafe { CStr::from_ptr(error_json) }.to_string_lossy().into_owned();
                unsafe { ffi::lp_string_free(error_json) };
                m
            };
            return Err(msg);
        }
        let raw = if result_json.is_null() {
            String::new()
        } else {
            let s = unsafe { CStr::from_ptr(result_json) }.to_string_lossy().into_owned();
            unsafe { ffi::lp_string_free(result_json) };
            s
        };
        return Ok(parse_ok(&raw));
    }

    let (tx, rx) = std::sync::mpsc::channel::<(bool, String)>();
    let user_data = Box::into_raw(Box::new(AsyncReply { tx })) as *mut c_void;
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
        drop(unsafe { Box::from_raw(user_data as *mut AsyncReply) });
        return Err(format!("{method}: lp_invoke_async dispatch failed rc={rc}"));
    }
    // The protocol owns timeout enforcement; the margin only guards a callback
    // that never fires.
    let wait = Duration::from_millis(timeout_ms as u64 + 10_000);
    let (ok, raw) = rx
        .recv_timeout(wait)
        .map_err(|_| format!("{method}: reply channel timed out"))?;
    if !ok {
        return Err(format!("{method}: {}", err_message(&raw)));
    }
    Ok(parse_ok(&raw))
}

/// Call a UNIVERSAL C++ module (libp2p_module), whose reply is a serialized
/// StdLogosResult envelope `{success, error, value}` — honor success/error and
/// return the inner `value`. Tolerates a double-encoded string envelope, and a
/// bare value for methods that don't wrap.
pub fn call_libp2p(method: &str, args: &Value, timeout_ms: i32) -> Result<Value, String> {
    let v = call_json(LIBP2P_MODULE, method, args, timeout_ms)?;
    let env = match v {
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
        return Ok(env.get("value").cloned().unwrap_or(Value::Null));
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
    let v = call_json(target, method, args, timeout_ms)?;
    match v {
        Value::String(s) if !s.is_empty() => {
            serde_json::from_str(&s).map_err(|e| format!("{method}: reply parse: {e}"))
        }
        Value::String(_) => Err(format!("{method}: empty reply")),
        other => Ok(other),
    }
}
