//! The `logos` scheme: a zkSign (Groth16 over BN254) by a logos-blockchain
//! node's KMS key `K` over the binding digest. The key never leaves the node;
//! `K` (32-byte little-endian Fr, as `/pow/status` prints it) is the identity.
//! Verification is offline against the bundled zkSign VK, or the operator's
//! `config.zksign_vk_path`.

use std::any::Any;

use rln_auth_vector::{norm_hex32, Identity};
#[cfg(feature = "verify")]
use rln_auth_vector::{Binding, Cfg, Check, Decoded, Outcome, Scheme, Transport};

pub const NAME: &str = "logos";
/// `K(32) ‖ zksig(128)`.
pub const PART_LEN: usize = 160;

/// A zkSign public key, 64 lowercase hex (little-endian Fr).
pub struct LogosKey(pub String);

impl Identity for LogosKey {
    fn canonical(&self) -> String {
        self.0.clone()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A key as an operator writes it: 64 hex, little-endian, a canonical BN254
/// scalar (the byte order a node prints).
pub fn parse_key(s: &str) -> Result<String, String> {
    let h = norm_hex32("config.allowlist entry", s)?;
    #[cfg(feature = "verify")]
    {
        let mut le = [0u8; 32];
        hex::decode_to_slice(&h, &mut le)
            .map_err(|e| format!("config.allowlist entry {s:?}: {e}"))?;
        if !zksign_light::is_canonical_fr(&le) {
            return Err(format!(
                "config.allowlist entry {s:?}: not a canonical BN254 scalar (big-endian paste?); \
                 keys are 32-byte little-endian, as /pow/status prints them"
            ));
        }
    }
    Ok(h)
}

pub struct Logos;

#[cfg(feature = "verify")]
impl Scheme for Logos {
    fn name(&self) -> &'static str {
        NAME
    }
    fn identity_noun(&self) -> &'static str {
        "public key"
    }
    fn parse_identity(&self, s: &str) -> Result<String, String> {
        parse_key(s)
    }
    /// `config.zksign_vk_path`: an operator's VK file instead of the bundled one.
    fn config(&self, raw: Option<&serde_json::Value>) -> Result<Cfg, String> {
        let vk = zksign_light::vk_from_config(raw.and_then(|c| c.get("zksign_vk_path")))?;
        Ok(Box::new(vk))
    }
    fn decode<'a>(&self, body: &'a [u8]) -> Outcome<Decoded<'a>> {
        if body.len() < PART_LEN {
            return Outcome::Reject(format!(
                "logos part must be 160 bytes (K 32 || zksig 128), got {}",
                body.len()
            ));
        }
        let (part, rest) = body.split_at(PART_LEN);
        Outcome::Ok(Decoded {
            claimed: Some(Box::new(LogosKey(hex::encode(&part[..32])))),
            part,
            rest,
        })
    }
    fn verify(
        &self,
        cfg: &dyn Any,
        _b: &Binding,
        digest: &[u8; 32],
        d: &Decoded<'_>,
        _t: &Transport<'_>,
    ) -> Check<Box<dyn Identity>> {
        let vk = cfg
            .downcast_ref::<zksign_light::VkSource>()
            .ok_or("logos scheme: config is not a VkSource")?;
        let k: [u8; 32] = d.part[..32]
            .try_into()
            .expect("invariant: a 32-byte range converts to [u8; 32]");
        let sig: [u8; 128] = d.part[32..160]
            .try_into()
            .expect("invariant: a 128-byte range converts to [u8; 128]");
        if k == zksign_light::zero_pk_le() {
            return Ok(Outcome::Reject("public key is the zero key".into()));
        }
        if let Err(e) = zksign_light::verify_sig(vk.get(), &k, digest, &sig) {
            return Ok(Outcome::Reject(e));
        }
        Ok(Outcome::Ok(Box::new(LogosKey(hex::encode(k)))))
    }
}

#[cfg(all(test, feature = "verify"))]
mod tests {
    use super::*;

    #[test]
    fn keys_normalise_and_must_be_canonical_scalars() {
        let k = zksign_light::zero_pk_le();
        let up = format!("0X{}", hex::encode(k).to_uppercase());
        assert_eq!(parse_key(&up).unwrap(), hex::encode(k));
        let mut big = [0xffu8; 32];
        big[0] = 0xff;
        assert!(parse_key(&hex::encode(big))
            .unwrap_err()
            .contains("big-endian paste"));
        assert!(parse_key("abc").is_err());
    }
}
