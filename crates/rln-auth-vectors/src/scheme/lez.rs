//! The `lez` scheme: a BIP-340 Schnorr signature by a LEZ public-account key
//! (secp256k1, untweaked, x-only) over the binding digest. The identity is the
//! key's LEE account id. Importing the same private key into a LEZ wallet
//! yields the same account id.

use std::any::Any;

use base58::FromBase58;
#[cfg(feature = "verify")]
use k256::schnorr::signature::hazmat::PrehashVerifier;
#[cfg(feature = "verify")]
use k256::schnorr::{Signature, VerifyingKey};
#[cfg(feature = "verify")]
use rln_auth_vector::{reason, Binding, Check, Decoded, Outcome, Scheme, Transport};
use rln_auth_vector::{strip_0x, Identity};
use sha2::{Digest, Sha256};

pub const NAME: &str = "lez";
/// `xonly(32) ‖ BIP-340 sig(64)`.
pub const PART_LEN: usize = 96;
/// LEE's public account-id prefix (exactly 32 bytes, zero-padded).
pub const LEE_ACCOUNT_ID_PREFIX: &[u8; 32] = b"/LEE/v0.3/AccountId/Public/\x00\x00\x00\x00\x00";

/// A LEE account id, 64 lowercase hex.
pub struct LezAccount(pub String);

impl Identity for LezAccount {
    fn canonical(&self) -> String {
        self.0.clone()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// LEE public account id: sha256(LEE_ACCOUNT_ID_PREFIX || xonly).
pub fn account_id(xonly: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(LEE_ACCOUNT_ID_PREFIX);
    h.update(xonly);
    h.finalize().into()
}

/// An account id as the wallet shows it — 64 hex (optional 0x, any case) or
/// base58 decoding to exactly 32 bytes — normalised to lowercase hex.
pub fn parse_account_id(s: &str) -> Result<String, String> {
    let s = s.trim();
    let h = strip_0x(s);
    if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(h.to_ascii_lowercase());
    }
    let bytes = s
        .from_base58()
        .map_err(|e| format!("account id '{s}': neither 64 hex nor base58 ({e:?})"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "account id '{s}': base58 decodes to {} bytes, want 32",
            bytes.len()
        ));
    }
    Ok(hex::encode(bytes))
}

pub struct Lez;

#[cfg(feature = "verify")]
impl Scheme for Lez {
    fn name(&self) -> &'static str {
        NAME
    }
    fn identity_noun(&self) -> &'static str {
        "account"
    }
    fn parse_identity(&self, s: &str) -> Result<String, String> {
        parse_account_id(s)
    }
    fn decode<'a>(&self, body: &'a [u8]) -> Outcome<Decoded<'a>> {
        if body.len() < PART_LEN {
            return Outcome::Reject(format!(
                "lez part must be 96 bytes (xonly pubkey 32 || BIP-340 sig 64), got {}",
                body.len()
            ));
        }
        let (part, rest) = body.split_at(PART_LEN);
        let xonly: [u8; 32] = part[..32]
            .try_into()
            .expect("invariant: a 32-byte range converts to [u8; 32]");
        Outcome::Ok(Decoded {
            claimed: Some(Box::new(LezAccount(hex::encode(account_id(&xonly))))),
            part,
            rest,
        })
    }
    fn verify(
        &self,
        _cfg: &dyn Any,
        _b: &Binding,
        digest: &[u8; 32],
        d: &Decoded<'_>,
        _t: &Transport<'_>,
    ) -> Check<Box<dyn Identity>> {
        let vk = match VerifyingKey::from_bytes(&d.part[..32]) {
            Ok(k) => k,
            Err(e) => return Ok(Outcome::Reject(format!("public key: {e}"))),
        };
        let sig = match Signature::try_from(&d.part[32..96]) {
            Ok(s) => s,
            Err(e) => return Ok(Outcome::Reject(format!("signature: {e}"))),
        };
        if vk.verify_prehash(digest, &sig).is_err() {
            return Ok(Outcome::Reject(reason::SIG_FAILED.into()));
        }
        let xonly: [u8; 32] = d.part[..32]
            .try_into()
            .expect("invariant: a 32-byte range converts to [u8; 32]");
        Ok(Outcome::Ok(Box::new(LezAccount(hex::encode(account_id(
            &xonly,
        ))))))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use base58::ToBase58;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::schnorr::SigningKey;
    use k256::SecretKey;

    // BIP-340 test vector 0: sk = 3.
    pub(crate) const BIP340_PK0: &str =
        "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
    // python3: hashlib.sha256(b"/LEE/v0.3/AccountId/Public/" + b"\0"*5 + pk).hexdigest(), base58 (Bitcoin alphabet).
    pub(crate) const PK0_ACCT_HEX: &str =
        "ec2cbcd4488075c4b30678c30351327fdf99f3fe703edc2999b68f8fd12bdbc8";
    pub(crate) const PK0_ACCT_B58: &str = "GtvnQVLsv8V34E3X9hMBR9hsUokapUgiE4o7vCU4VMB5";

    pub(crate) fn sk_bytes(n: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[31] = n;
        b
    }

    /// LEE's x-only derivation: the x coordinate of the (un-normalised) point.
    pub(crate) fn lee_xonly(sk: &[u8; 32]) -> [u8; 32] {
        let pk = SecretKey::from_slice(sk).unwrap().public_key();
        let enc = pk.to_encoded_point(false);
        (*enc.x().unwrap()).into()
    }

    pub(crate) fn odd_y(sk: &[u8; 32]) -> bool {
        let pk = SecretKey::from_slice(sk).unwrap().public_key();
        pk.to_encoded_point(true).as_bytes()[0] == 0x03
    }

    #[test]
    fn lee_prefix_is_32_bytes() {
        assert_eq!(LEE_ACCOUNT_ID_PREFIX.len(), 32);
        assert!(LEE_ACCOUNT_ID_PREFIX.starts_with(b"/LEE/v0.3/AccountId/Public/"));
    }

    #[test]
    fn xonly_equals_lee_derivation_for_even_and_odd_keys() {
        let mut seen_odd = false;
        let mut seen_even = false;
        for n in 1..=8u8 {
            let sk = sk_bytes(n);
            if odd_y(&sk) {
                seen_odd = true
            } else {
                seen_even = true
            }
            let vk_bytes: [u8; 32] = SigningKey::from_bytes(&sk)
                .unwrap()
                .verifying_key()
                .to_bytes()
                .into();
            assert_eq!(vk_bytes, lee_xonly(&sk), "sk {n}");
        }
        assert!(seen_odd && seen_even);
    }

    #[test]
    fn account_id_known_answer_bip340_vector0() {
        assert_eq!(hex::encode(lee_xonly(&sk_bytes(3))), BIP340_PK0);
        let pk: [u8; 32] = hex::decode(BIP340_PK0).unwrap().try_into().unwrap();
        let acct = account_id(&pk);
        assert_eq!(hex::encode(acct), PK0_ACCT_HEX);
        assert_eq!(acct.to_base58(), PK0_ACCT_B58);
        assert_eq!(parse_account_id(PK0_ACCT_B58).unwrap(), PK0_ACCT_HEX);
        assert_eq!(
            parse_account_id(&format!(" 0X{} ", PK0_ACCT_HEX.to_uppercase())).unwrap(),
            PK0_ACCT_HEX
        );
        assert!(
            parse_account_id("nope").is_err(),
            "decodes to fewer than 32 bytes"
        );
        assert!(parse_account_id("0OIl").is_err(), "not base58 at all");
    }
}
