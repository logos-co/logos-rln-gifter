// RLN membership gifter: client requests + gifter serve over libp2p
// FEATURE: RLN membership gifter logos-core module

use serde_json::json;

mod auth;
mod client;
mod lp;
mod server;
mod wire;

pub trait RlnGifterModule: Send + 'static {
    /// Client: request a gifted membership from a gifter peer. Args
    /// `{gifterPeerId, gifterMultiaddr, config?, seed, rate?, authKey?, attestation?}`
    /// → `{leaf_index, id_commitment, auth_success, identity_adopted, tx_hash?}`.
    fn request(&mut self, args_json: String) -> String;
    /// Gifter node: mount the gifter protocol and serve inbound requests. Args
    /// `{config, wallet, allowlist?, trustedCAs?, consumedNullifiersPath?, maxRateLimit?}`
    /// → `{mounted:true}`.
    fn serve(&mut self, args_json: String) -> String;
    /// Relay an arbitrary libp2p_module call so the UI can read its return value
    /// (a C++ LogosResult marshals to null through the QML bridge; a module-to-
    /// module SDK call returns the real value). `{method, args}` → the reply JSON.
    /// Used by the app to bring up the libp2p node (rlnEnable/start) before request.
    fn libp2p_call(&mut self, args_json: String) -> String;
    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {}
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

#[derive(Default)]
struct RlnGifter {}

impl RlnGifterModule for RlnGifter {
    // Return a plain String (not Result): the codegen maps a Rust Result to
    // returnType "LogosResult", which the host marshals to null in the UI; a
    // plain String maps to QString and passes through. Errors are {"error":...}.
    fn request(&mut self, args_json: String) -> String {
        client::request(&args_json)
            .map(|v| v.to_string())
            .unwrap_or_else(|e| json!({ "error": e }).to_string())
    }

    fn serve(&mut self, args_json: String) -> String {
        server::serve(&args_json)
            .map(|v| v.to_string())
            .unwrap_or_else(|e| json!({ "error": e }).to_string())
    }

    fn libp2p_call(&mut self, args_json: String) -> String {
        let a: serde_json::Value = match serde_json::from_str(&args_json) {
            Ok(v) => v,
            Err(e) => return json!({ "error": e.to_string() }).to_string(),
        };
        let Some(method) = a.get("method").and_then(|m| m.as_str()) else {
            return json!({ "error": "missing method" }).to_string();
        };
        let args = a.get("args").cloned().unwrap_or_else(|| json!([]));
        let proxy = logos_rust_sdk::LogosModuleSDK::new().plugin("libp2p_module");
        match proxy.call_json(method, &args) {
            Ok(v) => v.to_string(),
            Err(e) => json!({ "error": format!("{e}") }).to_string(),
        }
    }

    // Record the owner thread and open the cross-module clients here, on the
    // host's main Qt thread, so background serve threads can reach them.
    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {
        lp::init(&[lp::LIBP2P_MODULE, lp::RLN_MODULE]);
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<RlnGifter>();
}
