//! Known answer: the zkSign recorded from a real node (0.3.0-rc.5) in the
//! pow-claim capture fixture (`pow-claim-core/tests/fixtures/real/meta.json`,
//! copied as `fixtures/pow_claim_real_meta.json`). The signed digest is the
//! pow-claim challenge, recomputed here; zksig = payload[106..234].

use blake2::{digest::consts::U32, Blake2b, Digest as _};
use serde_json::Value;
use zksign_light::hex32_bytes;
use zksign_light::verify::{default_vk, verify_sig, zero_pk_le, PreparedVk, DEFAULT_VK_JSON};

const SIG_OFF: usize = 106;

struct Fixture {
    k: [u8; 32],
    digest: [u8; 32],
    zksig: [u8; 128],
}

fn fixture() -> Fixture {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/pow_claim_real_meta.json");
    let m: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let s = |k: &str| m[k].as_str().unwrap().to_string();
    let payload = hex::decode(s("payload_hex")).unwrap();
    assert_eq!(payload.len(), SIG_OFF + 128);
    let mut zksig = [0u8; 128];
    zksig.copy_from_slice(&payload[SIG_OFF..]);

    // pow-claim challenge: Blake2b-256(DOMAIN ‖ u8 len(aud) ‖ aud ‖ idc ‖ rate_max LE ‖ pow_nullifier).
    let aud = s("audience");
    let mut h = Blake2b::<U32>::new();
    h.update(b"logos:rln:gifter:pow-claim:v1\0");
    h.update([aud.len() as u8]);
    h.update(aud.as_bytes());
    h.update(hex32_bytes("idc", &s("id_commitment_hex")).unwrap());
    h.update(m["rate_max"].as_u64().unwrap().to_le_bytes());
    h.update(hex32_bytes("nul", &s("pow_nullifier")).unwrap());
    Fixture {
        k: hex32_bytes("k", &s("k")).unwrap(),
        digest: h.finalize().into(),
        zksig,
    }
}

#[test]
fn real_signature_accepts() {
    let f = fixture();
    verify_sig(default_vk().unwrap(), &f.k, &f.digest, &f.zksig).unwrap();
    // A VK prepared from the same JSON text behaves identically.
    let vk = PreparedVk::from_json(DEFAULT_VK_JSON).unwrap();
    verify_sig(&vk, &f.k, &f.digest, &f.zksig).unwrap();
}

#[test]
fn flipped_proof_parts_reject() {
    let f = fixture();
    let vk = default_vk().unwrap();
    for (part, off) in [
        ("pi_a", 0usize),
        ("pi_b", 32),
        ("pi_b hi", 95),
        ("pi_c", 96),
    ] {
        let mut z = f.zksig;
        z[off] ^= 0x01;
        let e = verify_sig(vk, &f.k, &f.digest, &z).unwrap_err();
        assert!(e.starts_with("zkSign signature invalid"), "{part}: {e}");
    }
}

#[test]
fn other_key_or_digest_rejects() {
    let f = fixture();
    let vk = default_vk().unwrap();
    let mut k = f.k;
    k[0] ^= 0x01;
    assert!(verify_sig(vk, &k, &f.digest, &f.zksig).is_err());
    let mut rev = f.k;
    rev.reverse();
    assert!(
        verify_sig(vk, &rev, &f.digest, &f.zksig).is_err(),
        "byte-reversed K must not verify"
    );
    let mut d = f.digest;
    d[31] ^= 0x01;
    assert!(verify_sig(vk, &f.k, &d, &f.zksig).is_err());
    assert!(verify_sig(vk, &zero_pk_le(), &f.digest, &f.zksig).is_err());
}

#[test]
fn non_canonical_key_and_bad_vk_are_reported() {
    let f = fixture();
    let e = verify_sig(default_vk().unwrap(), &[0xff; 32], &f.digest, &f.zksig).unwrap_err();
    assert!(e.contains("(K:"), "{e}");
    assert!(PreparedVk::from_json("{}").is_err());
    let e = PreparedVk::from_path("/nonexistent/vk.json").err().unwrap();
    assert!(e.starts_with("config.zksign_vk_path"), "{e}");
}

#[test]
fn vk_with_the_wrong_public_input_count_is_an_error() {
    let mut vk: Value = serde_json::from_str(DEFAULT_VK_JSON).unwrap();
    let ic = vk["IC"].as_array_mut().unwrap();
    assert_eq!(ic.len(), zksign_light::verify::PUBLIC_INPUTS + 1);
    ic.pop();
    vk["nPublic"] = serde_json::json!(32);
    let e = PreparedVk::from_json(&vk.to_string()).err().unwrap();
    assert!(
        e.contains("zkSign vk shape") && e.contains("33 public inputs"),
        "{e}"
    );
}

#[test]
fn zero_pk_le_is_canonical_and_stable() {
    let z = zero_pk_le();
    assert_ne!(z, [0u8; 32]);
    assert!(zksign_light::is_canonical_fr(&z));
    assert!(!zksign_light::is_canonical_fr(&[0xff; 32]));
    assert_eq!(z, zero_pk_le());
}

#[test]
fn vk_cache_reuses_a_prepared_vk_until_the_file_changes() {
    use std::sync::Arc;
    use zksign_light::verify::vk_from_path_cached;

    let dir = std::env::temp_dir().join(format!("zksign-vk-cache-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("vk.json");
    let path_str = path.to_str().unwrap();
    std::fs::write(&path, DEFAULT_VK_JSON).unwrap();

    let first = vk_from_path_cached(path_str).unwrap();
    let hit = vk_from_path_cached(path_str).unwrap();
    assert!(
        Arc::ptr_eq(&first, &hit),
        "unchanged file must hit the cache"
    );

    // Trailing whitespace keeps the JSON valid and changes the length (part of the key).
    std::fs::write(&path, format!("{DEFAULT_VK_JSON}\n\n")).unwrap();
    let second = vk_from_path_cached(path_str).unwrap();
    assert!(
        !Arc::ptr_eq(&first, &second),
        "a changed file must yield a new handle"
    );

    // The evicted handle stays usable.
    let f = fixture();
    verify_sig(first.as_ref(), &f.k, &f.digest, &f.zksig).unwrap();
    verify_sig(second.as_ref(), &f.k, &f.digest, &f.zksig).unwrap();
    std::fs::remove_dir_all(&dir).ok();
}
