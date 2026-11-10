// Minimal protobuf wire codec for the RLN membership gifter messages, matching
// nim-libp2p minprotobuf (standard protobuf: varint keys, LEN-delimited for
// bytes/strings, varint for uint64/bool). No external protobuf dependency.
// The wire is byte-identical to the nwaku port.

use base58::FromBase58;
use base64::Engine;
use sha2::{Digest, Sha256};

/// The wire's failure message prefixes: the client reads them to tell a
/// request nothing acted on (another allocator may) from one that may have
/// landed (stop, the credential is spent).
pub const NOT_SUBMITTED_PREFIX: &str = "not submitted: ";
pub const UNCONFIRMED_PREFIX: &str = "unconfirmed: ";

// The wire carries authentication_type as opaque bytes — vector names live in
// the rln_auth_vector crate and in gifter configuration, not here.
pub const RLN_GIFTER_CODEC: &str = "/logos/rln/membership/1.0.0";

/// The service id an allocator advertises through libp2p service discovery
/// (LIP-158 Appendix A: the protocol id). One advertisement per node: a
/// registrar makes a second advertisement from the same IP wait a whole ad
/// lifetime (nim-libp2p's Sybil defence), so what the node serves rides in
/// the advertisement's data instead of in further ids.
pub const RLN_GIFTER_SERVICE_ID: &str = RLN_GIFTER_CODEC;
/// First byte of the advertised data: its layout version.
pub const SERVICE_DATA_VERSION: u8 = b'1';
/// libp2p caps a service's data at 33 bytes: the version byte plus eight
/// base64 digests of 3 bytes (4 chars each, no padding).
pub const MAX_ADVERTISED_PAIRS: usize = 8;
const PAIR_DIGEST_LEN: usize = 3;

/// A served (registry, auth type) pair as an advertisement names it: the
/// first 3 bytes of sha256(`<registry canonical hex>/<auth_type>`). An open
/// allocator (no verifiers) serves the empty auth type.
pub fn pair_digest(registry_hex: &str, auth_type: &str) -> [u8; PAIR_DIGEST_LEN] {
    let h = Sha256::digest(format!("{registry_hex}/{auth_type}").as_bytes());
    let mut d = [0u8; PAIR_DIGEST_LEN];
    d.copy_from_slice(&h[..PAIR_DIGEST_LEN]);
    d
}

/// The data an allocator advertises for its served pairs: the version byte
/// and the sorted, deduplicated digests, base64 without padding. Text, so
/// it crosses the module wire as a JSON string unchanged.
pub fn service_data(pairs: &[(&str, &str)]) -> Result<String, String> {
    let mut digests: Vec<[u8; PAIR_DIGEST_LEN]> =
        pairs.iter().map(|(r, t)| pair_digest(r, t)).collect();
    digests.sort_unstable();
    digests.dedup();
    if digests.len() > MAX_ADVERTISED_PAIRS {
        return Err(format!(
            "an advertisement carries at most {MAX_ADVERTISED_PAIRS} (registry, auth type) pairs, not {}",
            digests.len()
        ));
    }
    let bytes: Vec<u8> = digests.concat();
    let mut out = String::with_capacity(1 + bytes.len() * 4 / 3);
    out.push(SERVICE_DATA_VERSION as char);
    out.push_str(&base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes));
    Ok(out)
}

/// Whether advertised data (the raw bytes of a discovery record's service
/// data) lists this pair. Data of another version or layout lists nothing.
pub fn service_data_lists(data: &[u8], registry_hex: &str, auth_type: &str) -> bool {
    let Some((&version, rest)) = data.split_first() else {
        return false;
    };
    if version != SERVICE_DATA_VERSION {
        return false;
    }
    let Ok(bytes) = base64::engine::general_purpose::STANDARD_NO_PAD.decode(rest) else {
        return false;
    };
    let want = pair_digest(registry_hex, auth_type);
    bytes.chunks_exact(PAIR_DIGEST_LEN).any(|c| c == want)
}

/// A registry's ConfigState account as callers write it — 64 hex (`0x` ok,
/// any case) or the base58 a wallet prints — as lowercase hex: the one form
/// the allocator keys its registries and its spent credentials by, and the one
/// it answers in `config_account_id`. The registry module takes either.
pub fn canonical_account(s: &str) -> Result<String, String> {
    let s = s.trim();
    let h = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(h.to_ascii_lowercase());
    }
    let bytes = s
        .from_base58()
        .map_err(|e| format!("config account '{s}': neither 64 hex nor base58 ({e:?})"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "config account '{s}': base58 decodes to {} bytes, want 32",
            bytes.len()
        ));
    }
    Ok(hex::encode(bytes))
}

/// The BN254 scalar field modulus r, big-endian.
const BN254_R_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// Why the registry would refuse this identity commitment, or None when it is
/// a canonical BN254 scalar. The registry reads the 32 bytes LITTLE-endian
/// and refuses zero or any value >= r (liblogos_lez_rln_module 5.1.0:
/// `invalid_commitment`); older registry modules submitted it, the guest
/// panicked, and the fee was charged anyway — so both the requester and the
/// gifter check before any verifier call or chain round-trip. The strings
/// mirror the lez module's kind so a caller can match `invalid_commitment`
/// whichever side refused.
pub fn commitment_refusal(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() != 32 {
        return Some("identity_commitment must be 32 bytes");
    }
    if bytes.iter().all(|&b| b == 0) {
        return Some("invalid_commitment: zero");
    }
    // Little-endian value vs r: compare from the most significant byte down.
    for (le_byte, r_byte) in bytes.iter().rev().zip(BN254_R_BE.iter()) {
        if le_byte < r_byte {
            return None;
        }
        if le_byte > r_byte {
            return Some(
                "invalid_commitment: not a BN254 field element (little-endian value >= r)",
            );
        }
    }
    Some("invalid_commitment: not a BN254 field element (little-endian value >= r)")
}

#[derive(Default, Clone)]
pub struct RlnGifterRequest {
    pub request_id: String,
    pub authentication_type: Vec<u8>,
    pub authentication_payload: Vec<u8>,
    pub identity_commitment: Vec<u8>,
    pub rate_limit: Option<u64>,
    /// The registry (ConfigState account) the membership is wanted on; field
    /// 100, beside the spec, as the reply's `config_account_id` is. Absent =
    /// whatever the allocator serves by default.
    pub config_account_id: Option<String>,
}

#[derive(Default, Clone)]
pub struct MembershipAllocationSuccess {
    pub leaf_index: u64,
    pub merkle_root: Vec<u8>,
    pub block_number: u64,
    pub transaction_hash: Vec<u8>,
    pub config_account_id: Option<String>,
}

#[derive(Default, Clone)]
pub struct MembershipAllocationFailure {
    pub error_message: String,
}

#[derive(Default, Clone)]
pub struct RlnGifterResponse {
    pub request_id: String,
    pub auth_success: bool,
    pub error: Option<String>,
    pub success: Option<MembershipAllocationSuccess>,
    pub failure: Option<MembershipAllocationFailure>,
}

// ---------------------------------------------------------------- low-level

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

fn put_len_field(out: &mut Vec<u8>, field: u64, data: &[u8]) {
    put_varint(out, (field << 3) | 2);
    put_varint(out, data.len() as u64);
    out.extend_from_slice(data);
}

fn put_varint_field(out: &mut Vec<u8>, field: u64, v: u64) {
    put_varint(out, field << 3);
    put_varint(out, v);
}

fn read_varint(buf: &[u8], i: &mut usize) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let b = *buf.get(*i)?;
        *i += 1;
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

// Copy: the field readers take it by value (clippy::needless_pass_by_value otherwise).
#[derive(Clone, Copy)]
enum FieldVal<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

// Walks length-delimited (wire 2) and varint (wire 0) fields — the only two the
// gifter schema uses. `f` receives each (field_number, value); a malformed frame
// returns Err.
fn walk_fields<'a, F: FnMut(u64, FieldVal<'a>)>(buf: &'a [u8], mut f: F) -> Result<(), String> {
    let mut i = 0usize;
    while i < buf.len() {
        let key = read_varint(buf, &mut i).ok_or("truncated field key")?;
        let field = key >> 3;
        match key & 7 {
            0 => {
                let v = read_varint(buf, &mut i).ok_or("truncated varint value")?;
                f(field, FieldVal::Varint(v));
            }
            2 => {
                let len = read_varint(buf, &mut i).ok_or("truncated length")? as usize;
                let end = i.checked_add(len).ok_or("length overflow")?;
                if end > buf.len() {
                    return Err("length exceeds buffer".into());
                }
                f(field, FieldVal::Bytes(&buf[i..end]));
                i = end;
            }
            w => return Err(format!("unsupported wire type {w}")),
        }
    }
    Ok(())
}

/// The field's bytes in the frame; a varint where bytes belong reads as none.
fn as_slice(v: FieldVal<'_>) -> &[u8] {
    match v {
        FieldVal::Bytes(b) => b,
        FieldVal::Varint(_) => &[],
    }
}

fn as_bytes(v: FieldVal) -> Vec<u8> {
    as_slice(v).to_vec()
}

fn as_string(v: FieldVal) -> String {
    match v {
        FieldVal::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
        FieldVal::Varint(_) => String::new(),
    }
}

fn as_u64(v: FieldVal) -> u64 {
    match v {
        FieldVal::Varint(n) => n,
        FieldVal::Bytes(_) => 0,
    }
}

// ---------------------------------------------------------------- encode

impl RlnGifterRequest {
    pub fn encode(&self) -> Vec<u8> {
        // Fields 2 and 3 are written unconditionally (even when empty), matching
        // the nim encoder, so the wire bytes are identical.
        let mut out = Vec::new();
        put_len_field(&mut out, 1, self.request_id.as_bytes());
        put_len_field(&mut out, 2, &self.authentication_type);
        put_len_field(&mut out, 3, &self.authentication_payload);
        put_len_field(&mut out, 4, &self.identity_commitment);
        if let Some(r) = self.rate_limit {
            put_varint_field(&mut out, 5, r);
        }
        if let Some(ref cfg) = self.config_account_id {
            put_len_field(&mut out, 100, cfg.as_bytes());
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<RlnGifterRequest, String> {
        let mut m = RlnGifterRequest::default();
        let mut have_id = false;
        let mut have_idc = false;
        walk_fields(buf, |field, v| match field {
            1 => {
                m.request_id = as_string(v);
                have_id = true;
            }
            2 => m.authentication_type = as_bytes(v),
            3 => m.authentication_payload = as_bytes(v),
            4 => {
                m.identity_commitment = as_bytes(v);
                have_idc = true;
            }
            5 => m.rate_limit = Some(as_u64(v)),
            100 => m.config_account_id = Some(as_string(v)),
            _ => {}
        })?;
        if !have_id {
            return Err("missing request_id".into());
        }
        if !have_idc {
            return Err("missing identity_commitment".into());
        }
        Ok(m)
    }
}

impl MembershipAllocationSuccess {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_varint_field(&mut out, 1, self.leaf_index);
        put_len_field(&mut out, 2, &self.merkle_root);
        put_varint_field(&mut out, 3, self.block_number);
        put_len_field(&mut out, 4, &self.transaction_hash);
        if let Some(ref cfg) = self.config_account_id {
            put_len_field(&mut out, 100, cfg.as_bytes());
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<MembershipAllocationSuccess, String> {
        let mut m = MembershipAllocationSuccess::default();
        walk_fields(buf, |field, v| match field {
            1 => m.leaf_index = as_u64(v),
            2 => m.merkle_root = as_bytes(v),
            3 => m.block_number = as_u64(v),
            4 => m.transaction_hash = as_bytes(v),
            100 => m.config_account_id = Some(as_string(v)),
            _ => {}
        })?;
        Ok(m)
    }
}

impl MembershipAllocationFailure {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_len_field(&mut out, 1, self.error_message.as_bytes());
        out
    }

    pub fn decode(buf: &[u8]) -> Result<MembershipAllocationFailure, String> {
        let mut m = MembershipAllocationFailure::default();
        walk_fields(buf, |field, v| {
            if field == 1 {
                m.error_message = as_string(v);
            }
        })?;
        Ok(m)
    }
}

impl RlnGifterResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_len_field(&mut out, 1, self.request_id.as_bytes());
        put_varint_field(&mut out, 2, self.auth_success as u64);
        if let Some(ref e) = self.error {
            put_len_field(&mut out, 3, e.as_bytes());
        }
        if let Some(ref s) = self.success {
            put_len_field(&mut out, 4, &s.encode());
        }
        if let Some(ref f) = self.failure {
            put_len_field(&mut out, 5, &f.encode());
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<RlnGifterResponse, String> {
        let mut m = RlnGifterResponse::default();
        let mut sub_err: Option<String> = None;
        let mut have_id = false;
        let mut have_auth = false;
        walk_fields(buf, |field, v| match field {
            1 => {
                m.request_id = as_string(v);
                have_id = true;
            }
            2 => {
                m.auth_success = as_u64(v) != 0;
                have_auth = true;
            }
            3 => m.error = Some(as_string(v)),
            4 => match MembershipAllocationSuccess::decode(as_slice(v)) {
                Ok(s) => m.success = Some(s),
                Err(e) => sub_err = Some(e),
            },
            5 => match MembershipAllocationFailure::decode(as_slice(v)) {
                Ok(f) => m.failure = Some(f),
                Err(e) => sub_err = Some(e),
            },
            _ => {}
        })?;
        if let Some(e) = sub_err {
            return Err(e);
        }
        if !have_id {
            return Err("missing request_id".into());
        }
        if !have_auth {
            return Err("missing auth_success".into());
        }
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertised_data_names_each_served_pair_once_and_fits_libp2p() {
        let (d, m) = (hex::encode([0xd; 32]), hex::encode([0xa; 32]));
        let pairs = [
            (d.as_str(), "peer-any"),
            (m.as_str(), "peer-any"),
            (d.as_str(), "eth-allowlist"),
            (d.as_str(), "peer-any"),
        ];
        let data = service_data(&pairs).unwrap();
        assert_eq!(data.len(), 1 + 3 * 4, "{data}");
        assert!(data.starts_with('1'));
        for (r, t) in &pairs {
            assert!(service_data_lists(data.as_bytes(), r, t), "{r}/{t}");
        }
        assert!(!service_data_lists(data.as_bytes(), &m, "eth-allowlist"));
        assert!(!service_data_lists(data.as_bytes(), &d, ""));
        assert!(!service_data_lists(b"", &d, "peer-any"));
        assert!(!service_data_lists(
            format!("2{}", &data[1..]).as_bytes(),
            &d,
            "peer-any"
        ));
        assert!(!service_data_lists(b"1not*base64", &d, "peer-any"));

        let open = service_data(&[(d.as_str(), "")]).unwrap();
        assert!(service_data_lists(open.as_bytes(), &d, ""));

        let types: Vec<String> = (0..9u8).map(|i| format!("t{i}")).collect();
        let eight: Vec<(&str, &str)> = types[..8]
            .iter()
            .map(|t| (d.as_str(), t.as_str()))
            .collect();
        assert_eq!(service_data(&eight).unwrap().len(), 33);
        let nine: Vec<(&str, &str)> = types.iter().map(|t| (d.as_str(), t.as_str())).collect();
        assert!(service_data(&nine).unwrap_err().contains("at most 8"));
        assert_eq!(service_data(&[]).unwrap(), "1");
    }

    #[test]
    fn commitment_refusal_mirrors_the_registry() {
        // r itself, little-endian: refused; r - 1: accepted.
        let mut r_le = BN254_R_BE;
        r_le.reverse();
        assert!(commitment_refusal(&r_le)
            .unwrap()
            .contains("invalid_commitment"));
        let mut r_minus_1 = r_le;
        r_minus_1[0] -= 1;
        assert_eq!(commitment_refusal(&r_minus_1), None);
        assert_eq!(
            commitment_refusal(&[0xff; 32]).unwrap(),
            "invalid_commitment: not a BN254 field element (little-endian value >= r)"
        );
        assert_eq!(
            commitment_refusal(&[0u8; 32]).unwrap(),
            "invalid_commitment: zero"
        );
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(commitment_refusal(&one), None);
        // Top byte 0x0a < 0x30: canonical whatever the rest holds.
        let mut small_top = [0xab; 32];
        small_top[31] = 0x0a;
        assert_eq!(commitment_refusal(&small_top), None);
        assert!(commitment_refusal(&[1u8; 31]).unwrap().contains("32 bytes"));
    }

    #[test]
    fn config_accounts_normalise_to_lowercase_hex() {
        let hex = "ab".repeat(32);
        assert_eq!(
            canonical_account(&format!(" 0X{} ", hex.to_uppercase())).unwrap(),
            hex
        );
        // base58 of 32 0xab bytes.
        let b58 = "CZ8YUVdk7znjrUmnb5n7kgySk9yRAsQDYmyCxzfSky9t";
        assert_eq!(canonical_account(b58).unwrap(), hex);
        assert!(canonical_account("ab0")
            .unwrap_err()
            .contains("neither 64 hex nor base58"));
        assert!(canonical_account("11").unwrap_err().contains("want 32"));
    }

    #[test]
    fn request_roundtrip() {
        let req = RlnGifterRequest {
            request_id: "abc123".into(),
            authentication_type: b"any-vector-string".to_vec(),
            authentication_payload: vec![1, 2, 3, 4],
            identity_commitment: vec![9u8; 32],
            rate_limit: Some(100),
            config_account_id: Some("cfgAccount".into()),
        };
        let dec = RlnGifterRequest::decode(&req.encode()).unwrap();
        assert_eq!(dec.request_id, "abc123");
        assert_eq!(dec.authentication_type, b"any-vector-string");
        assert_eq!(dec.authentication_payload, vec![1, 2, 3, 4]);
        assert_eq!(dec.identity_commitment, vec![9u8; 32]);
        assert_eq!(dec.rate_limit, Some(100));
        assert_eq!(dec.config_account_id.as_deref(), Some("cfgAccount"));
    }

    #[test]
    fn response_success_roundtrip() {
        let resp = RlnGifterResponse {
            request_id: "r1".into(),
            auth_success: true,
            error: None,
            success: Some(MembershipAllocationSuccess {
                leaf_index: 56,
                merkle_root: vec![7u8; 32],
                block_number: 1234,
                transaction_hash: vec![0xab, 0xcd],
                config_account_id: Some("cfgAccount".into()),
            }),
            failure: None,
        };
        let dec = RlnGifterResponse::decode(&resp.encode()).unwrap();
        assert!(dec.auth_success);
        let s = dec.success.unwrap();
        assert_eq!(s.leaf_index, 56);
        assert_eq!(s.block_number, 1234);
        assert_eq!(s.transaction_hash, vec![0xab, 0xcd]);
        assert_eq!(s.config_account_id.as_deref(), Some("cfgAccount"));
    }

    #[test]
    fn a_varint_where_a_sub_message_belongs_decodes_as_an_empty_one() {
        // request_id "r", auth_success 1, then fields 4 and 5 as varints
        // (keys 0x20, 0x28: wire type 0) instead of length-delimited.
        let buf = [0x0A, 0x01, b'r', 0x10, 0x01, 0x20, 0x07, 0x28, 0x00];
        let dec = RlnGifterResponse::decode(&buf).unwrap();
        let s = dec.success.unwrap();
        assert_eq!((s.leaf_index, s.block_number), (0, 0));
        assert!(s.merkle_root.is_empty() && s.transaction_hash.is_empty());
        assert_eq!(s.config_account_id, None);
        assert_eq!(dec.failure.unwrap().error_message, "");
        // A length-delimited sub-message that does not parse fails the frame.
        let bad = [0x0A, 0x01, b'r', 0x10, 0x01, 0x22, 0x01, 0x0A];
        assert_eq!(
            RlnGifterResponse::decode(&bad).err().as_deref(),
            Some("truncated length")
        );
    }

    #[test]
    fn known_request_wire_bytes() {
        // Field keys: 1->0x0A, 2->0x12, 3->0x1A, 4->0x22, 5->0x28 — the standard
        // protobuf encoding minprotobuf produces.
        let req = RlnGifterRequest {
            request_id: "x".into(),
            authentication_type: vec![],
            authentication_payload: vec![],
            identity_commitment: vec![0xff],
            rate_limit: Some(1),
            config_account_id: None,
        };
        assert_eq!(
            req.encode(),
            vec![0x0A, 0x01, b'x', 0x12, 0x00, 0x1A, 0x00, 0x22, 0x01, 0xff, 0x28, 0x01]
        );
        // Field 100, wire type 2: key (100 << 3) | 2 = 802 = varint A2 06.
        let with_cfg = RlnGifterRequest {
            config_account_id: Some("c".into()),
            ..req
        };
        let mut want = vec![
            0x0A, 0x01, b'x', 0x12, 0x00, 0x1A, 0x00, 0x22, 0x01, 0xff, 0x28, 0x01,
        ];
        want.extend_from_slice(&[0xA2, 0x06, 0x01, b'c']);
        assert_eq!(with_cfg.encode(), want);
        assert_eq!(
            RlnGifterRequest::decode(&want)
                .unwrap()
                .config_account_id
                .as_deref(),
            Some("c")
        );
    }
}
