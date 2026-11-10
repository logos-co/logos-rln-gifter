//! The `eth` scheme: a secp256k1 recoverable ECDSA signature by an Ethereum
//! wallet. The exception to the binding rule: the signed message is the
//! EIP-191 `personal_sign` envelope over the LOWERCASE HEX of the bare
//! commitment, so any wallet (`personal_sign`, `cast wallet sign`) can produce
//! it; rate and audience are NOT bound. The recovered address is the identity.

use std::any::Any;

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use rln_auth_vector::Identity;
#[cfg(feature = "verify")]
use rln_auth_vector::{reason, Binding, Check, Decoded, Outcome, Scheme, Transport};

pub const NAME: &str = "eth";
/// `r ‖ s ‖ recid`, recid 0/1 (27/28 accepted on verify).
pub const PART_LEN: usize = 65;

/// Lowercase `0x` + 40 hex.
pub struct EthAddress(pub String);

impl Identity for EthAddress {
    fn canonical(&self) -> String {
        self.0.clone()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut k = Keccak::v256();
    let mut out = [0u8; 32];
    k.update(data);
    k.finalize(&mut out);
    out
}

/// The EIP-191 personal_sign digest: keccak256 over the envelope wrapping the
/// LOWERCASE HEX of the 32-byte commitment — the signed message is the
/// human-readable hex string a wallet displays, not raw bytes.
pub fn eip191_digest(id_commitment: &[u8; 32]) -> [u8; 32] {
    let hexs = hex::encode(id_commitment);
    let mut msg = format!("\x19Ethereum Signed Message:\n{}", hexs.len()).into_bytes();
    msg.extend_from_slice(hexs.as_bytes());
    keccak256(&msg)
}

/// Lowercase 0x address of a secp256k1 public key.
pub fn address_of(vk: &VerifyingKey) -> String {
    let enc = vk.to_encoded_point(false);
    let raw = &enc.as_bytes()[1..]; // 64 bytes: X || Y
    let h = keccak256(raw);
    format!("0x{}", hex::encode(&h[12..]))
}

/// Recover the signer's lowercase 0x address from a 65-byte recoverable
/// signature (r||s||recid; recid raw 0/1 or 27/28-offset) over the EIP-191
/// envelope of `id_commitment`.
pub fn recover_signer(id_commitment: &[u8; 32], sig: &[u8]) -> Result<String, String> {
    if sig.len() != PART_LEN {
        return Err(format!("signature must be 65 bytes, got {}", sig.len()));
    }
    let digest = eip191_digest(id_commitment);
    let recid_byte = if sig[64] >= 27 { sig[64] - 27 } else { sig[64] };
    let recid = RecoveryId::from_byte(recid_byte).ok_or("invalid recovery id")?;
    let signature = Signature::from_slice(&sig[0..64]).map_err(|e| format!("sig: {e}"))?;
    // EIP-2: only low-S signatures; (r, n-s) with the flipped recid would
    // otherwise be a second valid encoding of the same signature.
    if signature.normalize_s().is_some() {
        return Err("high-S signature (EIP-2 requires s <= n/2)".into());
    }
    let vk = VerifyingKey::recover_from_prehash(&digest, &signature, recid)
        .map_err(|e| format!("recovery failed: {e}"))?;
    Ok(address_of(&vk))
}

/// An allowlist entry normalised to lowercase `0x` + 40 hex (a bare 40-hex
/// address gets the `0x`); anything else is an operator error naming it.
pub fn normalize_address(entry: &str) -> Result<String, String> {
    let t = entry.trim().to_ascii_lowercase();
    let h = t.strip_prefix("0x").unwrap_or(&t);
    if h.len() != 40 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "config.allowlist entry {entry:?}: expected a 0x address (40 hex chars)"
        ));
    }
    Ok(format!("0x{h}"))
}

pub struct Eth;

#[cfg(feature = "verify")]
impl Scheme for Eth {
    fn name(&self) -> &'static str {
        NAME
    }
    fn identity_noun(&self) -> &'static str {
        "address"
    }
    fn parse_identity(&self, s: &str) -> Result<String, String> {
        normalize_address(s)
    }
    fn decode<'a>(&self, body: &'a [u8]) -> Outcome<Decoded<'a>> {
        if body.len() < PART_LEN {
            return Outcome::Reject(format!(
                "eth part must be 65 bytes (r||s||recid), got {}",
                body.len()
            ));
        }
        let (part, rest) = body.split_at(PART_LEN);
        Outcome::Ok(Decoded {
            claimed: None,
            part,
            rest,
        })
    }
    fn verify(
        &self,
        _cfg: &dyn Any,
        b: &Binding,
        _digest: &[u8; 32],
        d: &Decoded<'_>,
        _t: &Transport<'_>,
    ) -> Check<Box<dyn Identity>> {
        Ok(match recover_signer(&b.id_commitment, d.part) {
            Ok(addr) => Outcome::Ok(Box::new(EthAddress(addr))),
            Err(e) => Outcome::Reject(reason::sig_failed(e)),
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    pub(crate) const PK42: [u8; 32] = [0x42; 32];
    pub(crate) const ADDR42: &str = "0x17c5185167401ed00cf5f5b2fc97d9bbfdb7d025";
    pub(crate) const IDC: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    // `cast wallet sign --private-key 0x42…42 "$IDC"` (foundry; EIP-191 over
    // the hex string, v = 27 + recid).
    pub(crate) const CAST_SIG: &str = "84b1aff4c2850be46cefd3e12e22349bc886dea47e7b0e509c2e3059f1035fc1606d3c249c695f72556bd1d12ff301671244780f72177a2e3f89a033a8dd94c81c";

    pub(crate) fn idc() -> [u8; 32] {
        hex::decode(IDC).unwrap().try_into().unwrap()
    }

    #[test]
    fn foundry_cast_signature_recovers() {
        let sig = hex::decode(CAST_SIG).unwrap();
        assert_eq!(recover_signer(&idc(), &sig).unwrap(), ADDR42);
        let sk = SigningKey::from_slice(&PK42).unwrap();
        assert_eq!(address_of(sk.verifying_key()), ADDR42);
    }

    #[test]
    fn recid_offsets_and_high_s() {
        let sk = SigningKey::from_slice(&PK42).unwrap();
        let digest = eip191_digest(&[0x11; 32]);
        let (sig, recid) = sk.sign_prehash_recoverable(&digest).unwrap();
        for offset in [0u8, 27] {
            let mut p = sig.to_bytes().to_vec();
            p.push(recid.to_byte() + offset);
            assert_eq!(
                recover_signer(&[0x11; 32], &p).unwrap(),
                ADDR42,
                "offset {offset}"
            );
        }
        let (r, s) = sig.split_scalars();
        let high = Signature::from_scalars(r, -*s).unwrap();
        let mut p = high.to_bytes().to_vec();
        p.push(recid.to_byte() ^ 1);
        assert!(recover_signer(&[0x11; 32], &p)
            .unwrap_err()
            .contains("high-S"));
        assert!(recover_signer(&[0x11; 32], &p[..64])
            .unwrap_err()
            .contains("65 bytes"));
    }

    #[test]
    fn addresses_normalise() {
        let up = ADDR42.to_uppercase().replace("0X", "0x");
        assert_eq!(normalize_address(&up).unwrap(), ADDR42);
        assert_eq!(normalize_address(&ADDR42[2..]).unwrap(), ADDR42);
        assert_eq!(
            normalize_address(&format!("  {} ", ADDR42.to_uppercase())).unwrap(),
            ADDR42
        );
        for bad in [
            "0x1234",
            "not-an-address",
            &format!("{ADDR42}00"),
            &format!("0x0x{}", &ADDR42[4..]),
        ] {
            assert!(normalize_address(bad)
                .unwrap_err()
                .contains(&format!("{bad:?}")));
        }
    }
}
