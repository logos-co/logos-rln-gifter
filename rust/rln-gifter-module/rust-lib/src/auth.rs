// Gifter server authentication: EIP-191 signer recovery (eth allowlist) and
// keycard IDENTIFY_CARD attestation verification (genuine-card), plus the
// append-only consumed-nullifier store. Ported from the gifter's eip191.nim +
// keycard_auth.nim; attestation verify reuses the vendored keycard_attest crate.
// FEATURE: RLN membership gifter authentication primitives

use std::collections::HashSet;

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use keycard_attest::attest::{bound_challenge, parse_attestation, verify_attestation};

fn keccak256(data: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut k = Keccak::v256();
    let mut out = [0u8; 32];
    k.update(data);
    k.finalize(&mut out);
    out
}

// The EIP-191 personal_sign digest: keccak256 over the envelope wrapping the
// LOWERCASE HEX of the 32-byte commitment (matching eip191.nim, so signatures
// produced against the nim gifter verify here unchanged).
fn eip191_digest(id_commitment: &[u8]) -> [u8; 32] {
    let hexs = hex::encode(id_commitment);
    let mut msg = format!("\x19Ethereum Signed Message:\n{}", hexs.len()).into_bytes();
    msg.extend_from_slice(hexs.as_bytes());
    keccak256(&msg)
}

/// Recover the signer's lowercase 0x Ethereum address from a 65-byte recoverable
/// signature (r||s||recid) over the EIP-191 envelope of `id_commitment`.
pub fn verify_eip191(id_commitment: &[u8], sig: &[u8]) -> Result<String, String> {
    if sig.len() != 65 {
        return Err(format!("signature must be 65 bytes, got {}", sig.len()));
    }
    let digest = eip191_digest(id_commitment);
    // Accept both raw recid (0/1) and the 27/28-offset form.
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

/// Verify a genuine-card IDENTIFY_CARD attestation TLV bound to `id_commitment`
/// against `trusted_cas`, returning the once-per-card nullifier as lowercase hex.
pub fn verify_keycard(
    payload: &[u8],
    id_commitment: &[u8],
    trusted_cas: &[[u8; 33]],
) -> Result<String, String> {
    let att = parse_attestation(payload).map_err(|e| format!("attestation parse failed: {e}"))?;
    let challenge = bound_challenge(id_commitment);
    let nullifier = verify_attestation(&att, trusted_cas, &challenge)
        .map_err(|e| format!("attestation verification failed: {e}"))?;
    Ok(hex::encode(nullifier))
}

/// Load the append-only consumed-nullifier store (lowercase hex, one per line).
/// Missing/unreadable file → empty set (a fresh gifter).
pub fn load_nullifiers(path: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    if path.is_empty() {
        return set;
    }
    if let Ok(contents) = std::fs::read_to_string(path) {
        for line in contents.lines() {
            let n = line.trim().to_lowercase();
            if !n.is_empty() {
                set.insert(n);
            }
        }
    }
    set
}

/// Append a consumed nullifier to the persistent store (no-op without a path),
/// so a gifter restart cannot re-grant a card.
pub fn append_nullifier(path: &str, nullifier_hex: &str) {
    if path.is_empty() {
        return;
    }
    use std::io::Write;
    match std::fs::OpenOptions::new().create(true).append(true).open(path) {
        Ok(mut f) => {
            let _ = writeln!(f, "{nullifier_hex}");
        }
        Err(e) => eprintln!("rln_gifter: failed to persist nullifier to {path}: {e}"),
    }
}
