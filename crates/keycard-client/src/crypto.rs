// Keycard secure-channel crypto: ECDH, PBKDF2 pairing, AES-256-CBC + CBC-MAC
// FEATURE: Keycard device-key RLN membership logos-core module

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use k256::ecdh::diffie_hellman;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{PublicKey, SecretKey};
use pbkdf2::pbkdf2_hmac_array;
use sha2::{Digest, Sha256, Sha512};
use unicode_normalization::UnicodeNormalization;

pub const PAIRING_TOKEN_SALT: &str = "Keycard Pairing Password Salt";

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn ecdh_generate(card_pub_bytes: &[u8]) -> Result<([u8; 32], Vec<u8>), String> {
    let mut rng = rand::thread_rng();
    let eph = SecretKey::random(&mut rng);
    let card_pub =
        PublicKey::from_sec1_bytes(card_pub_bytes).map_err(|e| format!("card pubkey: {e}"))?;
    let shared = diffie_hellman(eph.to_nonzero_scalar(), card_pub.as_affine());
    let secret: [u8; 32] = shared.raw_secret_bytes()[..]
        .try_into()
        .map_err(|_| "ecdh len")?;
    let eph_pub = eph.public_key().to_encoded_point(false).as_bytes().to_vec();
    Ok((secret, eph_pub))
}

fn nfkd(s: &str) -> Vec<u8> {
    s.nfkd().collect::<String>().into_bytes()
}

pub fn pairing_secret_hash(pairing_pass: &str) -> [u8; 32] {
    pbkdf2_hmac_array::<Sha256, 32>(&nfkd(pairing_pass), &nfkd(PAIRING_TOKEN_SALT), 50000)
}

pub fn derive_session_keys(
    secret: &[u8],
    pairing_key: &[u8],
    card_data: &[u8],
) -> ([u8; 32], [u8; 32], [u8; 16]) {
    let salt = &card_data[..32];
    let iv: [u8; 16] = card_data[32..48]
        .try_into()
        .expect("invariant: a 16-byte range converts to [u8; 16]");
    let mut h = Sha512::new();
    h.update(secret);
    h.update(pairing_key);
    h.update(salt);
    let data = h.finalize();
    let enc: [u8; 32] = data[..32]
        .try_into()
        .expect("invariant: SHA-512 output is 64 bytes");
    let mac: [u8; 32] = data[32..64]
        .try_into()
        .expect("invariant: SHA-512 output is 64 bytes");
    (enc, mac, iv)
}

fn append_padding(data: &[u8]) -> Vec<u8> {
    let pad = 16 - (data.len() % 16);
    let mut out = data.to_vec();
    out.push(0x80);
    out.extend(std::iter::repeat_n(0u8, pad - 1));
    out
}

fn remove_padding(mut data: Vec<u8>) -> Vec<u8> {
    let mut i = data.len();
    while i > 0 {
        i -= 1;
        if data[i] == 0x80 {
            break;
        }
    }
    data.truncate(i);
    data
}

fn xor16(a: &[u8], b: &[u8]) -> [u8; 16] {
    let mut o = [0u8; 16];
    for i in 0..16 {
        o[i] = a[i] ^ b[i];
    }
    o
}

fn cbc_encrypt_raw(cipher: &Aes256, iv: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut prev = [0u8; 16];
    prev.copy_from_slice(iv);
    for chunk in data.chunks(16) {
        let mut b = aes::Block::from(xor16(chunk, &prev));
        cipher.encrypt_block(&mut b);
        prev.copy_from_slice(&b);
        out.extend_from_slice(&b);
    }
    out
}

fn cbc_decrypt_raw(cipher: &Aes256, iv: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut prev = [0u8; 16];
    prev.copy_from_slice(iv);
    for chunk in data.chunks(16) {
        #[allow(
            deprecated,
            reason = "generic-array 0.14.9 deprecates the crate; 0.14.7, pinned by some lockfiles, does not"
        )]
        let mut b = aes::Block::clone_from_slice(chunk);
        cipher.decrypt_block(&mut b);
        let p = xor16(&b, &prev);
        prev.copy_from_slice(chunk);
        out.extend_from_slice(&p);
    }
    out
}

pub fn encrypt_data(data: &[u8], enc_key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes256::new_from_slice(enc_key)
        .expect("invariant: secure-channel keys are 32 bytes (derive_session_keys)");
    cbc_encrypt_raw(&cipher, iv, &append_padding(data))
}

pub fn decrypt_data(data: &[u8], enc_key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes256::new_from_slice(enc_key)
        .expect("invariant: secure-channel keys are 32 bytes (derive_session_keys)");
    remove_padding(cbc_decrypt_raw(&cipher, iv, data))
}

pub fn calculate_mac(meta: &[u8; 16], data: &[u8], mac_key: &[u8]) -> [u8; 16] {
    let cipher = Aes256::new_from_slice(mac_key)
        .expect("invariant: secure-channel keys are 32 bytes (derive_session_keys)");
    let mut buf = meta.to_vec();
    buf.extend_from_slice(&append_padding(data));
    let ct = cbc_encrypt_raw(&cipher, &[0u8; 16], &buf);
    let n = ct.len();
    let mut mac = [0u8; 16];
    mac.copy_from_slice(&ct[n - 32..n - 16]);
    mac
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const IV: [u8; 16] = [
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe,
        0xff,
    ];

    #[test]
    fn cbc_matches_openssl_aes_256_cbc_on_iso7816_padding() {
        // `openssl enc -aes-256-cbc -nopad` of the message ‖ 0x80 ‖ 0x00 × 9.
        let ct = encrypt_data(b"keycard secure channel", &KEY, &IV);
        assert_eq!(
            hex::encode(&ct),
            "492c3d783c680e478d0863f6f2c216cb7980d98602c71d82d7e215159f07a704"
        );
        assert_eq!(decrypt_data(&ct, &KEY, &IV), b"keycard secure channel");
    }
}
