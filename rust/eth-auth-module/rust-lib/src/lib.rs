// EIP-191 eth-allowlist VERIFIER for gifted RLN registration — the server-side
// half of the eth auth vector. The producer half (wallet signing) is external:
// requesters pass the pre-made signature via authPayload / auth_payload.
// Returning the recovered address as the nullifier gives one-membership-per-
// address through the gifter's shared, PERSISTED replay store (the old
// built-in's consumed-address set was in-memory only).
// FEATURE: RLN gifter eth-allowlist auth vector (verify)

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use rln_auth_vector::{dispatch_verify, AuthVector, Verdict, VerifyRequest};

pub trait EthAuthModule: Send + 'static {
    /// rln_auth_vector VERIFY_METHOD for auth_type "eth-allowlist". One
    /// JSON-string arg (VerifyRequest); payload: 65-byte recoverable EIP-191
    /// personal_sign signature (r||s||recid) over the lowercase hex of the
    /// 32-byte identity commitment; config: `{"allowlist": ["0x…", …]}`.
    /// Accepts with the recovered address as the nullifier.
    /// `{"ok", "reason"?, "nullifier"?}` or `{"error"}`.
    fn verify_auth(&mut self, args_json: String) -> String;
    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {}
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

#[derive(Default)]
struct EthAuth {}

struct EthAllowlistVector;

fn keccak256(data: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut k = Keccak::v256();
    let mut out = [0u8; 32];
    k.update(data);
    k.finalize(&mut out);
    out
}

// The EIP-191 personal_sign digest: keccak256 over the envelope wrapping the
// LOWERCASE HEX of the 32-byte commitment (matching the original gifter's
// eip191.nim, so signatures produced against it verify here unchanged).
fn eip191_digest(id_commitment: &[u8]) -> [u8; 32] {
    let hexs = hex::encode(id_commitment);
    let mut msg = format!("\x19Ethereum Signed Message:\n{}", hexs.len()).into_bytes();
    msg.extend_from_slice(hexs.as_bytes());
    keccak256(&msg)
}

/// Recover the signer's lowercase 0x address from a 65-byte recoverable
/// signature (r||s||recid; recid raw 0/1 or 27/28-offset) over the EIP-191
/// envelope of `id_commitment`.
fn recover_signer(id_commitment: &[u8], sig: &[u8]) -> Result<String, String> {
    if sig.len() != 65 {
        return Err(format!("signature must be 65 bytes, got {}", sig.len()));
    }
    let digest = eip191_digest(id_commitment);
    let recid_byte = if sig[64] >= 27 { sig[64] - 27 } else { sig[64] };
    let recid = RecoveryId::from_byte(recid_byte).ok_or("invalid recovery id")?;
    let signature = Signature::from_slice(&sig[0..64]).map_err(|e| format!("sig: {e}"))?;
    let vk = VerifyingKey::recover_from_prehash(&digest, &signature, recid)
        .map_err(|e| format!("recovery failed: {e}"))?;
    let enc = vk.to_encoded_point(false);
    let raw = &enc.as_bytes()[1..]; // 64 bytes: X || Y
    let h = keccak256(raw);
    Ok(format!("0x{}", hex::encode(&h[12..])))
}

impl AuthVector for EthAllowlistVector {
    fn auth_type(&self) -> &'static str {
        rln_auth_vector::ETH_ALLOWLIST_AUTH_TYPE
    }

    // Malformed config is an Err (operator mistake, error envelope); a
    // signature that doesn't recover or an unlisted signer is a REJECT
    // verdict (untrusted input, normal flow).
    fn verify(&self, req: &VerifyRequest) -> Result<Verdict, String> {
        let allowlist = req
            .config
            .as_ref()
            .and_then(|c| c.get("allowlist"))
            .and_then(|v| v.as_array())
            .ok_or("config.allowlist (array of 0x addresses) is required")?;
        let allowlist: Vec<String> = allowlist
            .iter()
            .map(|e| e.as_str().map(str::to_lowercase).ok_or("allowlist entries must be strings"))
            .collect::<Result<_, _>>()?;
        if allowlist.is_empty() {
            return Err("config.allowlist is empty — nothing can verify".into());
        }

        let sig = match hex::decode(req.payload_hex.trim_start_matches("0x")) {
            Ok(s) => s,
            Err(e) => return Ok(Verdict::reject(format!("payload hex: {e}"))),
        };
        let id_commitment = match hex::decode(req.id_commitment_hex.trim_start_matches("0x")) {
            Ok(c) => c,
            Err(e) => return Ok(Verdict::reject(format!("id_commitment hex: {e}"))),
        };
        let signer = match recover_signer(&id_commitment, &sig) {
            Ok(s) => s,
            Err(e) => return Ok(Verdict::reject(format!("signature verification failed: {e}"))),
        };
        if !allowlist.contains(&signer) {
            return Ok(Verdict::reject(format!("address not allowlisted: {signer}")));
        }
        Ok(Verdict::accept(Some(signer)))
    }
}

impl EthAuthModule for EthAuth {
    // Plain String (not Result): codegen maps Result to LogosResult, which the
    // host nulls through the UI bridge; errors travel as {"error":...}.
    fn verify_auth(&mut self, args_json: String) -> String {
        dispatch_verify(&args_json, &[&EthAllowlistVector])
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<EthAuth>();
}
