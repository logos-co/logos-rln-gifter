// RLN membership gifter: client requests + gifter serve over libp2p
// (libp2p_module is this module's declared dependency; logoscore loads it
// first).

use serde_json::json;

mod auth;
mod client;
mod lp;
mod server;
mod wire;

// OWNERSHIP: the generated host keeps the instance in a process-lifetime any-box, so the module owns all its data.
pub trait RlnGifterModule: Send + 'static {
    /// Client: request a gifted membership from an allocator. Args
    /// `{config?, identityCommitment, rate?, authType?, authPayload?,
    ///  authProvider?, authArgs?, discover?, gifterPeerId?, gifterMultiaddr?}`.
    /// config names the registry (ConfigState account). Allocators
    /// advertising the (registry, authType) pair through libp2p service
    /// discovery are tried first (discover, default true; needs config and a
    /// node with discovery mounted) while none has read the request; the
    /// configured gifterPeerId+gifterMultiaddr pair, if any, comes after
    /// them. authType names the auth vector in the wire's OPEN
    /// authentication_type vocabulary — any type the target allocator's
    /// authVerifiers accept; this module knows no vector by name. The payload
    /// comes from authPayload (raw hex, verbatim) or an authProvider module
    /// implementing the rln_auth_vector producer contract (authArgs forwarded
    /// verbatim); no authType at all is an unauthenticated request for an
    /// open allocator
    /// → `{leaf_index, id_commitment, auth_success, identity_adopted,
    ///  gifterPeerId, discovered, tx_hash?, config_account?}`.
    /// A failure is `{error, gifterPeerId?, discovered?}`: the two keys name
    /// the last allocator tried when its own reply refused (a refusal, a
    /// registration not submitted or unconfirmed). Discovery outcomes inside
    /// the error text: `discovery unavailable: <why>` (this node cannot
    /// discover: no discovery mounted, libp2p down), `discovery not joined:
    /// no connected peer after 20s` and `no allocator advertises
    /// <registry>/<authType>` (both may pass on a later try). With no
    /// allocator granting and no pair configured the error is `no allocator
    /// granted and none is configured: <what each try said>`.
    fn request(&mut self, args_json: String) -> String;
    /// Client: the allocators currently advertising a (registry, authType)
    /// pair through libp2p service discovery. Args `{config, authType?}`
    /// → `{serviceId, candidates:[{peerId, addrs}], joined, peers}`:
    /// candidates is empty when none is placed yet or this node joined no
    /// peer within 20 s (`joined` false); `peers` is its outbound peer count.
    /// A node that cannot discover is the error `discovery unavailable:
    /// <why>`.
    fn discover(&mut self, args_json: String) -> String;
    /// Allocator: mount the gifter protocol and serve inbound requests. Args
    /// `{config, wallet, registries?, authVerifiers?, consumedNullifiersPath?,
    ///  maxRateLimit?, advertise?, advertiseAddrs?}` → `{mounted:true,
    ///  registries, advertised, serviceId?, serviceData?, advertisedToPeers?,
    ///  advertisePending?, advertiseError?}`.
    /// authVerifiers maps each accepted authentication_type to its verifier
    /// module (`{"<type>": {module, config?}}` — an rln_auth_vector
    /// VERIFY_METHOD implementor; config rides along opaquely on every
    /// call). ALL vectors are such plugins — this module ships none. No
    /// authVerifiers = an open allocator. advertise (default true) publishes
    /// the served (registry, type) pairs under the protocol id through
    /// libp2p service discovery; a node without discovery mounted serves
    /// unadvertised (advertiseError says so) unless advertise is an explicit
    /// true, which makes that an error. advertiseAddrs (multiaddr strings)
    /// advertises a record signed for those addresses instead of the listen
    /// addresses. The advertisement is placed at once; advertisedToPeers is
    /// the outbound peer count then, and one placed with none is re-placed
    /// once outbound peers appear.
    fn serve(&mut self, args_json: String) -> String;
    /// Relay an arbitrary libp2p_module call so the UI can read its return value
    /// (a C++ LogosResult marshals to null through the QML bridge; a module-to-
    /// module SDK call returns the real value). `{method, args}` → the reply JSON.
    /// Used by the app to bring up the libp2p node (rlnEnable/start) before request.
    fn libp2p_call(&mut self, args_json: String) -> String;
    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {}
}

// The generated scaffold lives in its own module so its lint expectations
// cover nothing hand-written; the crate root re-exports its public items.
#[expect(
    clippy::allow_attributes_without_reason,
    clippy::bind_instead_of_map,
    clippy::extra_unused_type_parameters,
    clippy::len_zero,
    clippy::not_unsafe_ptr_arg_deref,
    clippy::redundant_closure,
    clippy::too_many_arguments,
    clippy::undocumented_unsafe_blocks,
    dead_code,
    unused_imports,
    reason = "generated by logos-lidl-gen"
)]
mod generated {
    use super::RlnGifterModule;

    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/generated/provider_gen.rs"
    ));
}
pub use generated::*;

#[derive(Default)]
struct RlnGifter {
    /// The allocator side; `serve` runs on the owner thread with `&mut self`.
    server: server::ServeState,
}

/// An entry point's reply: the value itself, or `{"error": why}`.
fn reply(r: Result<serde_json::Value, String>) -> String {
    match r {
        Ok(v) => v.to_string(),
        Err(e) => json!({ "error": e }).to_string(),
    }
}

impl RlnGifterModule for RlnGifter {
    // Return a plain String (not Result): the codegen maps a Rust Result to
    // returnType "LogosResult", which the host marshals to null in the UI; a
    // plain String maps to QString and passes through. Errors are {"error":...}.
    fn request(&mut self, args_json: String) -> String {
        match client::request(&args_json) {
            Ok(v) => v.to_string(),
            Err(f) => f.json().to_string(),
        }
    }

    fn discover(&mut self, args_json: String) -> String {
        reply(client::discover(&args_json))
    }

    fn serve(&mut self, args_json: String) -> String {
        reply(server::serve(&mut self.server, &args_json))
    }

    fn libp2p_call(&mut self, args_json: String) -> String {
        let a: serde_json::Value = match serde_json::from_str(&args_json) {
            Ok(v) => v,
            Err(e) => return json!({ "error": e.to_string() }).to_string(),
        };
        let Some(method) = a.get("method").and_then(|m| m.as_str()) else {
            return json!({ "error": "missing method" }).to_string();
        };
        let no_args = json!([]);
        let args = a.get("args").unwrap_or(&no_args);
        let proxy = logos_rust_sdk::LogosModuleSDK::new().plugin("libp2p_module");
        reply(proxy.call_json(method, args).map_err(|e| e.to_string()))
    }

    // Record the owner thread and open the cross-module clients here, on the
    // host's main Qt thread, so background serve threads can reach them.
    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {
        lp::init(&[lp::LIBP2P_MODULE, lp::LEZ_RLN_MODULE]);
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<RlnGifter>();
}
