// Verify a Keycard IDENTIFY_CARD attestation and bind it to an RLN commitment
// FEATURE: Keycard-rooted RLN identities

use crate::error::Error;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

const TAG_SIGNATURE_TEMPLATE: u8 = 0xA0;
const TAG_CERTIFICATE: u8 = 0x8A;
const TAG_DER_SEQUENCE: u8 = 0x30;
const CERTIFICATE_LEN: usize = 98;

/// Domain-separates the challenge the card signs so a genuine attestation is
/// bound to one RLN `id_commitment` and can't be replayed for another.
pub const ATTEST_DOMAIN: &[u8] = b"logos/rln/keycard-attest/1";

/// The Status production IdentApplet CA public key (compressed secp256k1),
/// confirmed byte-for-byte from a genuine retail Keycard v3.1 on 2026-07-09
/// (IDENTIFY_CARD recovered exactly this key). An attestation that recovers this
/// CA proves the card is a genuine Status device; it is the zone's trust anchor.
pub const STATUS_PRODUCTION_CA: [u8; 33] = [
    0x02, 0x9a, 0xb9, 0x9e, 0xe1, 0xe7, 0xa7, 0x1b, 0xdf, 0x45, 0xb3, 0xf9, 0xc5, 0x8c, 0x99, 0x86,
    0x6f, 0xf1, 0x29, 0x4d, 0x2c, 0x1e, 0x30, 0x4e, 0x22, 0x8a, 0x86, 0xe1, 0x0c, 0x33, 0x43, 0x50,
    0x1c,
];

/// A parsed IDENTIFY_CARD response: the card's identity pubkey, the CA
/// signature over it (proving the card is genuine), and the card's signature
/// over the challenge (proving liveness + binding to `id_commitment`).
pub struct Attestation {
    pub ident_pub: [u8; 33],
    pub ca_sig: [u8; 65],
    pub challenge_sig: Signature,
}

/// The 32-byte challenge a client must have the card sign: `SHA256(domain ||
/// id_commitment)`. Recomputed by the verifier from the requested commitment,
/// so the attestation only counts for the commitment it was produced for.
pub fn bound_challenge(id_commitment: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ATTEST_DOMAIN);
    h.update(id_commitment);
    h.finalize().into()
}

/// The once-per-card nullifier: `keccak256(ident_pub)`. Derived from the card's
/// manufacturer identity key, which survives factory reset, so a card can claim
/// a free membership only once regardless of how many wallet keys it generates.
pub fn nullifier(ident_pub: &[u8; 33]) -> [u8; 32] {
    let mut k = Keccak::v256();
    let mut out = [0u8; 32];
    k.update(ident_pub);
    k.finalize(&mut out);
    out
}

fn read_len(buf: &[u8], i: usize) -> Result<(usize, usize), Error> {
    let l0 = *buf.get(i).ok_or_else(|| Error::InvalidInput("tlv length truncated".into()))?;
    if l0 < 0x80 {
        Ok((l0 as usize, 1))
    } else if l0 == 0x81 {
        Ok((*buf.get(i + 1).ok_or_else(|| Error::InvalidInput("tlv len81".into()))? as usize, 2))
    } else if l0 == 0x82 {
        let hi = *buf.get(i + 1).ok_or_else(|| Error::InvalidInput("tlv len82".into()))? as usize;
        let lo = *buf.get(i + 2).ok_or_else(|| Error::InvalidInput("tlv len82".into()))? as usize;
        Ok(((hi << 8) | lo, 3))
    } else {
        Err(Error::InvalidInput("unsupported tlv length form".into()))
    }
}

fn find_tag(buf: &[u8], tag: u8) -> Result<(&[u8], &[u8]), Error> {
    let mut i = 0;
    while i + 1 < buf.len() {
        let (vlen, lhdr) = read_len(buf, i + 1)?;
        let vstart = i + 1 + lhdr;
        let vend = vstart
            .checked_add(vlen)
            .filter(|e| *e <= buf.len())
            .ok_or_else(|| Error::InvalidInput("tlv value out of range".into()))?;
        if buf[i] == tag {
            return Ok((&buf[vstart..vend], &buf[i..vend]));
        }
        i = vend;
    }
    Err(Error::InvalidInput(format!("tlv tag {tag:#04x} not found")))
}

/// Parse the IDENTIFY_CARD TLV `A0 { 8A <98-byte cert>, <DER challenge sig> }`,
/// where the 98-byte cert is `ident_pub(33) || ca_sig(65)`.
pub fn parse_attestation(tlv: &[u8]) -> Result<Attestation, Error> {
    let (template, _) = find_tag(tlv, TAG_SIGNATURE_TEMPLATE)?;
    let (cert, _) = find_tag(template, TAG_CERTIFICATE)?;
    if cert.len() != CERTIFICATE_LEN {
        return Err(Error::InvalidInput("certificate must be 98 bytes".into()));
    }
    let mut ident_pub = [0u8; 33];
    ident_pub.copy_from_slice(&cert[0..33]);
    let mut ca_sig = [0u8; 65];
    ca_sig.copy_from_slice(&cert[33..98]);
    let (_, der_full) = find_tag(template, TAG_DER_SEQUENCE)?;
    let challenge_sig = Signature::from_der(der_full)
        .map_err(|e| Error::InvalidInput(format!("challenge sig DER: {e}")))?;
    Ok(Attestation { ident_pub, ca_sig, challenge_sig })
}

/// Verify a genuine-card attestation bound to `expected_challenge`, returning
/// the once-per-card nullifier. Fails unless (1) the cert signature recovers a
/// CA in `trusted_cas` and (2) the card's challenge signature verifies against
/// `ident_pub` over `expected_challenge` — the binding keycard-go never checks.
pub fn verify_attestation(
    att: &Attestation,
    trusted_cas: &[[u8; 33]],
    expected_challenge: &[u8; 32],
) -> Result<[u8; 32], Error> {
    let msg = Sha256::digest(att.ident_pub);
    let recid = RecoveryId::from_byte(att.ca_sig[64])
        .ok_or_else(|| Error::InvalidInput("bad CA recovery id".into()))?;
    let ca_sig = Signature::from_slice(&att.ca_sig[0..64])
        .map_err(|e| Error::InvalidInput(format!("CA sig: {e}")))?;
    let ca = VerifyingKey::recover_from_prehash(msg.as_slice(), &ca_sig, recid)
        .map_err(|e| Error::InvalidInput(format!("CA recover: {e}")))?;
    let ca_point = ca.to_encoded_point(true);
    if !trusted_cas.iter().any(|t| t.as_slice() == ca_point.as_bytes()) {
        return Err(Error::Backend("attestation CA is not trusted".into()));
    }
    let ident = VerifyingKey::from_sec1_bytes(&att.ident_pub)
        .map_err(|e| Error::InvalidInput(format!("ident pub: {e}")))?;
    // The card's JavaCard ECDSA emits high-S signatures; k256's verifier rejects
    // non-canonical S, so normalize to low-S before verifying the raw challenge.
    let sig = att.challenge_sig.normalize_s().unwrap_or(att.challenge_sig);
    ident
        .verify_prehash(expected_challenge, &sig)
        .map_err(|_| Error::InvalidSignature)?;
    Ok(nullifier(&att.ident_pub))
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOLDEN_TLV: &str = "a081ab8a620365c18485fe7018e11cb992011426803aa8e843c63aab9657aed7d3ee4b85a62a11188ada267db3312a84e1be27c01c736a89da7a1fe4f7e90ce297e74f00008e2bfdb06058374abfc1c026386d16ead7bbc19bc0645d2e7acf7b953169bbc1ac0130450220364c5ca937b7ca42861978f086d206cc569ef0bb2ea4c7de08929c2fcca7434d022100c87699ce4f977e6a7a4800343db9b6842b91ca873e56dfe3327d19a2d01af14e";
    const GOLDEN_CHALLENGE: &str =
        "63acd6e02a8b5783551ff2836a9cbdf237c115c3ff018b943f044e6a69b19fe7";
    const TEST_CA: &str = "02fc929321aa94fea085b166994aa66590116252cf0235a03accaa2c8ab4595de5";
    const IDENT_PUB: &str = "0365c18485fe7018e11cb992011426803aa8e843c63aab9657aed7d3ee4b85a62a";

    fn arr32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }
    fn arr33(s: &str) -> [u8; 33] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    #[test]
    fn parses_ident_pub() {
        let att = parse_attestation(&hex::decode(GOLDEN_TLV).unwrap()).unwrap();
        assert_eq!(hex::encode(att.ident_pub), IDENT_PUB);
    }

    // Golden keycard-go vector: recovers the test CA AND (unlike keycard-go's
    // no-op) actually verifies the challenge signature over the RAW 32-byte
    // challenge -- settling that the card signs the challenge un-rehashed.
    #[test]
    fn golden_vector_verifies_raw_challenge() {
        let att = parse_attestation(&hex::decode(GOLDEN_TLV).unwrap()).unwrap();
        let null =
            verify_attestation(&att, &[arr33(TEST_CA)], &arr32(GOLDEN_CHALLENGE)).unwrap();
        assert_eq!(null, nullifier(&att.ident_pub));
    }

    #[test]
    fn untrusted_ca_rejected() {
        let att = parse_attestation(&hex::decode(GOLDEN_TLV).unwrap()).unwrap();
        let err = verify_attestation(&att, &[[2u8; 33]], &arr32(GOLDEN_CHALLENGE)).unwrap_err();
        assert!(matches!(err, Error::Backend(_)));
    }

    // The binding: a challenge the card did not sign (e.g. one derived from a
    // different id_commitment) is rejected -- this is what stops replay.
    #[test]
    fn tampered_challenge_rejected() {
        let att = parse_attestation(&hex::decode(GOLDEN_TLV).unwrap()).unwrap();
        let mut bad = arr32(GOLDEN_CHALLENGE);
        bad[0] ^= 0x01;
        let err = verify_attestation(&att, &[arr33(TEST_CA)], &bad).unwrap_err();
        assert_eq!(err, Error::InvalidSignature);
        // A bound challenge for some commitment likewise won't match this vector.
        let other = bound_challenge(&[0x11; 32]);
        assert!(verify_attestation(&att, &[arr33(TEST_CA)], &other).is_err());
    }

    #[test]
    fn bound_challenge_is_deterministic_and_commitment_specific() {
        let idc = [0xABu8; 32];
        assert_eq!(bound_challenge(&idc), bound_challenge(&idc));
        assert_ne!(bound_challenge(&idc), bound_challenge(&[0xACu8; 32]));
    }
}
