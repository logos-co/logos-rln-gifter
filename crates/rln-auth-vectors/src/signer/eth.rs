//! The eth signer: a secp256k1 key signing the EIP-191 envelope over the
//! bare commitment hex — byte-for-byte what `cast wallet sign "<hex>"` does.

use k256::ecdsa::SigningKey;
use rln_auth_vector::{Binding, Identity, Signer};
use serde_json::Value;

use super::{private_key_arg, KeySource};
use crate::scheme::eth::{address_of, eip191_digest, EthAddress, NAME};

// OWNERSHIP: the module supplies and the signer owns the key source (its key store, a fixed key);
// the registry needs it `'static`, so a module shares its store by `Arc`, not by borrow.
pub struct EthSigner(pub Box<dyn KeySource>);

impl EthSigner {
    fn key(&self, args: Option<&Value>) -> Result<SigningKey, String> {
        let bytes = match private_key_arg(args)? {
            Some(k) => k,
            None => self.0.key(args)?,
        };
        SigningKey::from_slice(&bytes).map_err(|e| format!("private key: {e}"))
    }
}

impl Signer for EthSigner {
    fn scheme(&self) -> &'static str {
        NAME
    }
    /// `r ‖ s ‖ recid` (recid 0/1); the binding digest is NOT what is signed.
    fn sign(
        &self,
        b: &Binding,
        _digest: &[u8; 32],
        args: Option<&Value>,
    ) -> Result<Vec<u8>, String> {
        let key = self.key(args)?;
        let (sig, recid) = key
            .sign_prehash_recoverable(&eip191_digest(&b.id_commitment))
            .map_err(|e| format!("sign: {e}"))?;
        let mut out = sig.to_bytes().to_vec();
        out.push(recid.to_byte());
        Ok(out)
    }
    fn identity(&self, args: Option<&Value>) -> Result<Box<dyn Identity>, String> {
        Ok(Box::new(EthAddress(address_of(
            self.key(args)?.verifying_key(),
        ))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheme::eth::tests::{idc, ADDR42, CAST_SIG, PK42};
    use crate::signer::StaticKey;

    #[test]
    fn matches_foundry_cast_vector() {
        let s = EthSigner(Box::new(StaticKey(PK42)));
        let b = Binding {
            id_commitment: idc(),
            rate_max: 100,
            audience: String::new(),
        };
        let ours = s.sign(&b, &[0; 32], None).unwrap();
        assert_eq!(
            hex::encode(&ours[..64]),
            &CAST_SIG[..128],
            "r||s differs from cast"
        );
        let v = u8::from_str_radix(&CAST_SIG[128..], 16).unwrap();
        assert_eq!(ours[64], v - 27);
        assert_eq!(s.identity(None).unwrap().canonical(), ADDR42);
    }

    #[test]
    fn private_key_arg_overrides_the_source() {
        let s = EthSigner(Box::new(StaticKey([1; 32])));
        let args = serde_json::json!({ "private_key": format!("0x{}", hex::encode(PK42)) });
        assert_eq!(s.identity(Some(&args)).unwrap().canonical(), ADDR42);
        assert_ne!(s.identity(None).unwrap().canonical(), ADDR42);
        let bad = serde_json::json!({ "private_key": "0x01" });
        assert!(s.identity(Some(&bad)).err().unwrap().contains("32 bytes"));
    }
}
