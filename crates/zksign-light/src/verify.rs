//! Offline zkSign (Groth16 over BN254) verification. Semantics are those of
//! the pow-claim verifier's `sig.rs` (itself from `tools/pow-claim-poc`): the
//! public inputs are `[K, zero_pk × 31, Fr::from_le_bytes_mod_order(digest)]`,
//! i.e. a single-key signature with the 31 unused slots holding the zero key.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use ark_ff::PrimeField as _;
use logos_blockchain_groth16::{
    fr_from_bytes, fr_from_bytes_unchecked, groth16_verify, CompressedGroth16Proof, Fr,
    Groth16PreparedVerificationKey, Groth16Proof, Groth16VerificationKey,
    Groth16VerificationKeyJsonDeser,
};
use logos_blockchain_poseidon2::{Digest as _, Poseidon2Bn254Hasher};

/// zkSign verification key bundled with the node at 0.3.0-rc.5 (circuits v0.5.7).
pub const DEFAULT_VK_JSON: &str = include_str!("../assets/zksign_vk_v0.5.7.json");

/// Public inputs of the zkSign circuit: K, 31 zero-key slots, the digest.
pub const PUBLIC_INPUTS: usize = 33;

pub struct PreparedVk(Groth16PreparedVerificationKey);

impl PreparedVk {
    /// Parses and prepares a snarkjs-format VK. A VK for another circuit
    /// (`IC` must hold `PUBLIC_INPUTS + 1` points) fails here, so a wrong
    /// operator VK is a config error rather than a reject on every request.
    pub fn from_json(vk_json: &str) -> Result<PreparedVk, String> {
        let de: Groth16VerificationKeyJsonDeser =
            serde_json::from_str(vk_json).map_err(|e| format!("zkSign vk json: {e}"))?;
        if de.ic.len() != PUBLIC_INPUTS + 1 {
            return Err(format!(
                "zkSign vk shape: IC has {} points ({} public inputs), want {} ({PUBLIC_INPUTS} public inputs)",
                de.ic.len(),
                de.ic.len().saturating_sub(1),
                PUBLIC_INPUTS + 1
            ));
        }
        let vk = Groth16VerificationKey::try_from(de)
            .map_err(|e| format!("zkSign vk convert: {e:?}"))?;
        Ok(PreparedVk(vk.into_prepared()))
    }

    pub fn from_path(path: &str) -> Result<PreparedVk, String> {
        let s = std::fs::read_to_string(path)
            .map_err(|e| format!("config.zksign_vk_path {path}: {e}"))?;
        Self::from_json(&s).map_err(|e| format!("config.zksign_vk_path {path}: {e}"))
    }
}

static DEFAULT_VK: OnceLock<Result<PreparedVk, String>> = OnceLock::new();

/// The bundled VK, prepared on first use.
// OWNERSHIP: a static-lifetime borrow of the process-wide prepared VK; a cached error is copied out.
pub fn default_vk() -> Result<&'static PreparedVk, String> {
    DEFAULT_VK
        .get_or_init(|| PreparedVk::from_json(DEFAULT_VK_JSON))
        .as_ref()
        .map_err(Clone::clone)
}

type VkKey = (String, Option<std::time::SystemTime>, u64);

/// A VK file prepared once per (path, mtime, len), so a VK replaced in place
/// is picked up on the next request without re-parsing on every call.
pub fn vk_from_path_cached(path: &str) -> Result<Arc<PreparedVk>, String> {
    // OWNERSHIP: process-wide cache; Mutex for concurrent verifiers, Arc so an evicted VK stays
    // alive for the requests still holding it.
    static CACHE: OnceLock<Mutex<HashMap<VkKey, Arc<PreparedVk>>>> = OnceLock::new();
    let meta = std::fs::metadata(path).map_err(|e| format!("config.zksign_vk_path {path}: {e}"))?;
    let key: VkKey = (path.to_string(), meta.modified().ok(), meta.len());
    let cache = CACHE.get_or_init(Default::default);
    if let Some(v) = cache.lock().unwrap_or_else(|p| p.into_inner()).get(&key) {
        return Ok(Arc::clone(v));
    }
    let v = Arc::new(PreparedVk::from_path(path)?);
    let mut c = cache.lock().unwrap_or_else(|p| p.into_inner());
    c.retain(|(p, _, _), _| p != path);
    c.insert(key, Arc::clone(&v));
    drop(c);
    Ok(v)
}

/// The VK a verifier uses: the bundled one or an operator's file.
// OWNERSHIP: the bundled VK is a static-lifetime borrow of DEFAULT_VK; a file VK is a cache Arc handle.
pub enum VkSource {
    Default(&'static PreparedVk),
    File(Arc<PreparedVk>),
}

impl VkSource {
    pub fn get(&self) -> &PreparedVk {
        match self {
            VkSource::Default(v) => v,
            VkSource::File(v) => v,
        }
    }
}

/// `config.zksign_vk_path` → [`VkSource`]: absent or `null` is the bundled
/// VK; a non-empty path is read through the cache; anything else is an
/// operator error.
pub fn vk_from_config(v: Option<&serde_json::Value>) -> Result<VkSource, String> {
    match v {
        None | Some(serde_json::Value::Null) => Ok(VkSource::Default(default_vk()?)),
        Some(serde_json::Value::String(p)) if !p.trim().is_empty() => {
            Ok(VkSource::File(vk_from_path_cached(p.trim())?))
        }
        Some(v) => Err(format!(
            "config.zksign_vk_path: expected a non-empty string, got {v}"
        )),
    }
}

/// Public key of the zero secret key: `Poseidon2::compress([KDF, 0])`,
/// `KDF = Fr::from_le_bytes(b"KDF")` (kms/keys zk/private.rs @ rc.5). zkSign
/// fixes 32 key slots; unused slots carry this key.
pub fn zero_pk() -> Fr {
    static Z: OnceLock<Fr> = OnceLock::new();
    *Z.get_or_init(|| {
        let kdf = fr_from_bytes_unchecked(b"KDF");
        Poseidon2Bn254Hasher::compress(&[kdf, Fr::from(0u64)])
    })
}

/// [`zero_pk`] as the 32-byte little-endian encoding a node would show.
pub fn zero_pk_le() -> [u8; 32] {
    use ark_ff::BigInteger as _;
    let mut out = [0u8; 32];
    out.copy_from_slice(&zero_pk().into_bigint().to_bytes_le());
    out
}

/// Whether `le` is a canonical little-endian BN254 scalar (`< p`), i.e. a
/// value a node could print as a public key.
pub fn is_canonical_fr(le: &[u8; 32]) -> bool {
    fr_from_bytes(le).is_ok()
}

/// `Ok(())` iff `zksig` is a valid zkSign by `K` over `digest`. Every failure
/// (non-canonical K, undecodable proof, invalid proof) is a reject reason.
pub fn verify_sig(
    vk: &PreparedVk,
    k_le: &[u8; 32],
    digest: &[u8; 32],
    zksig: &[u8; 128],
) -> Result<(), String> {
    let k = fr_from_bytes(k_le).map_err(|e| format!("zkSign signature invalid (K: {e})"))?;
    let comp = CompressedGroth16Proof::from_bytes(zksig);
    let proof = Groth16Proof::try_from(&comp)
        .map_err(|e| format!("zkSign signature invalid (proof decode: {e:?})"))?;
    let mut inputs = Vec::with_capacity(PUBLIC_INPUTS);
    inputs.push(k);
    inputs.extend(std::iter::repeat_n(zero_pk(), PUBLIC_INPUTS - 2));
    inputs.push(Fr::from_le_bytes_mod_order(digest));
    match groth16_verify(&vk.0, &proof, &inputs) {
        Ok(true) => Ok(()),
        Ok(false) => Err("zkSign signature invalid (proof does not verify)".into()),
        Err(e) => Err(format!("zkSign signature invalid (verify: {e})")),
    }
}
