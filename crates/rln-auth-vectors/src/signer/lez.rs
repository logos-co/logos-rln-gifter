//! The lez signer: a secp256k1 key used as a LEZ public-account key
//! (untweaked, x-only) signing the binding digest with BIP-340.

use base58::ToBase58;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::schnorr::SigningKey;
use k256::SecretKey;
use rand_core::RngCore;
use rln_auth_vector::{strip_0x, Binding, Identity, Signer};
use serde_json::{json, Value};

use super::{private_key_arg, KeySource};
use crate::scheme::lez::{account_id, LezAccount, NAME};

/// A private key as given (not BIP-340-normalised), so what is persisted and
/// imported elsewhere is the caller's own scalar.
#[derive(Clone, Debug)]
pub struct LezKey(pub [u8; 32]);

impl LezKey {
    pub fn parse(hex_str: &str) -> Result<Self, String> {
        let bytes = hex::decode(strip_0x(hex_str)).map_err(|e| format!("private key hex: {e}"))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|b: Vec<u8>| format!("private key must be 32 bytes, got {}", b.len()))?;
        SigningKey::from_bytes(&arr).map_err(|e| format!("private key: {e}"))?;
        Ok(LezKey(arr))
    }

    pub fn random() -> Self {
        LezKey(SecretKey::random(&mut rand_core::OsRng).to_bytes().into())
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// LEE's x-only key: the x coordinate of the public point (identical
    /// whether or not BIP-340 normalises the scalar to even Y).
    pub fn xonly(&self) -> [u8; 32] {
        let pk = SecretKey::from_slice(&self.0)
            .expect("invariant: LezKey holds a valid scalar (checked by parse, made by random)")
            .public_key();
        (*pk.to_encoded_point(false)
            .x()
            .expect("invariant: a public key is never the identity point"))
        .into()
    }

    /// `{"account_id","account_id_base58","public_key"}`.
    pub fn identity_json(&self) -> Value {
        let xonly = self.xonly();
        let acct = account_id(&xonly);
        json!({
            "account_id": hex::encode(acct),
            "account_id_base58": acct.to_base58(),
            "public_key": hex::encode(xonly),
        })
    }

    /// `xonly(32) ‖ BIP-340 sig(64)` over `digest`.
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>, String> {
        let sk = SigningKey::from_bytes(&self.0).map_err(|e| format!("private key: {e}"))?;
        let mut aux = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut aux);
        let sig = sk
            .sign_prehash_with_aux_rand(digest, &aux)
            .map_err(|e| format!("sign: {e}"))?;
        let mut out = self.xonly().to_vec();
        out.extend_from_slice(&sig.to_bytes());
        Ok(out)
    }
}

// OWNERSHIP: the module supplies and the signer owns the key source (its key store, a fixed key);
// the registry needs it `'static`, so a module shares its store by `Arc`, not by borrow.
pub struct LezSigner(pub Box<dyn KeySource>);

impl LezSigner {
    fn key(&self, args: Option<&Value>) -> Result<LezKey, String> {
        let bytes = match private_key_arg(args)? {
            Some(k) => k,
            None => self.0.key(args)?,
        };
        SigningKey::from_bytes(&bytes).map_err(|e| format!("private key: {e}"))?;
        Ok(LezKey(bytes))
    }
}

impl Signer for LezSigner {
    fn scheme(&self) -> &'static str {
        NAME
    }
    fn sign(
        &self,
        _b: &Binding,
        digest: &[u8; 32],
        args: Option<&Value>,
    ) -> Result<Vec<u8>, String> {
        self.key(args)?.sign_digest(digest)
    }
    fn identity(&self, args: Option<&Value>) -> Result<Box<dyn Identity>, String> {
        Ok(Box::new(LezAccount(hex::encode(account_id(
            &self.key(args)?.xonly(),
        )))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::schnorr::signature::hazmat::PrehashVerifier;
    use k256::schnorr::{Signature, VerifyingKey};

    use crate::scheme::lez::tests::{
        lee_xonly, odd_y, sk_bytes, BIP340_PK0, PK0_ACCT_B58, PK0_ACCT_HEX,
    };

    #[test]
    fn bip340_vector0_identity_and_signature() {
        let key = LezKey::parse(&hex::encode(sk_bytes(3))).unwrap();
        let id = key.identity_json();
        assert_eq!(id["public_key"], BIP340_PK0);
        assert_eq!(id["account_id"], PK0_ACCT_HEX);
        assert_eq!(id["account_id_base58"], PK0_ACCT_B58);
        let part = key.sign_digest(&[0x42; 32]).unwrap();
        assert_eq!(part.len(), 96);
        assert_eq!(hex::encode(&part[..32]), BIP340_PK0);
        let vk = VerifyingKey::from_bytes(&part[..32]).unwrap();
        vk.verify_prehash(&[0x42; 32], &Signature::try_from(&part[32..]).unwrap())
            .unwrap();
    }

    #[test]
    fn odd_y_keys_sign_under_their_lee_xonly() {
        let odd = (1..=20u8).map(sk_bytes).find(odd_y).expect("an odd-Y key");
        let key = LezKey(odd);
        assert_eq!(key.xonly(), lee_xonly(&odd));
        let part = key.sign_digest(&[7; 32]).unwrap();
        let vk = VerifyingKey::from_bytes(&part[..32]).unwrap();
        vk.verify_prehash(&[7; 32], &Signature::try_from(&part[32..]).unwrap())
            .unwrap();
    }

    #[test]
    fn parse_validates_and_random_differs() {
        assert!(LezKey::parse("00").unwrap_err().contains("32 bytes"));
        assert!(
            LezKey::parse(&"00".repeat(32)).is_err(),
            "zero scalar is not a key"
        );
        assert_ne!(LezKey::random().0, LezKey::random().0);
    }
}
