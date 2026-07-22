// Minimal protobuf wire codec for the RLN membership gifter messages, matching
// nim-libp2p minprotobuf (standard protobuf: varint keys, LEN-delimited for
// bytes/strings, varint for uint64/bool). No external protobuf dependency.
// FEATURE: RLN membership gifter wire codec (byte-identical to the nwaku port)

pub const ETH_ALLOWLIST_AUTH_TYPE: &str = "eth-allowlist";
pub const KEYCARD_ATTEST_AUTH_TYPE: &str = "keycard-attestation";
pub const RLN_GIFTER_CODEC: &str = "/logos/rln/membership/1.0.0";

#[derive(Default, Clone)]
pub struct RlnGifterRequest {
    pub request_id: String,
    pub authentication_type: Vec<u8>,
    pub authentication_payload: Vec<u8>,
    pub identity_commitment: Vec<u8>,
    pub rate_limit: Option<u64>,
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

fn as_bytes(v: FieldVal) -> Vec<u8> {
    match v {
        FieldVal::Bytes(b) => b.to_vec(),
        FieldVal::Varint(_) => Vec::new(),
    }
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
            4 => match MembershipAllocationSuccess::decode(&as_bytes(v)) {
                Ok(s) => m.success = Some(s),
                Err(e) => sub_err = Some(e),
            },
            5 => match MembershipAllocationFailure::decode(&as_bytes(v)) {
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
    fn request_roundtrip() {
        let req = RlnGifterRequest {
            request_id: "abc123".into(),
            authentication_type: KEYCARD_ATTEST_AUTH_TYPE.as_bytes().to_vec(),
            authentication_payload: vec![1, 2, 3, 4],
            identity_commitment: vec![9u8; 32],
            rate_limit: Some(100),
        };
        let dec = RlnGifterRequest::decode(&req.encode()).unwrap();
        assert_eq!(dec.request_id, "abc123");
        assert_eq!(dec.authentication_type, KEYCARD_ATTEST_AUTH_TYPE.as_bytes());
        assert_eq!(dec.authentication_payload, vec![1, 2, 3, 4]);
        assert_eq!(dec.identity_commitment, vec![9u8; 32]);
        assert_eq!(dec.rate_limit, Some(100));
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
    fn known_request_wire_bytes() {
        // Field keys: 1->0x0A, 2->0x12, 3->0x1A, 4->0x22, 5->0x28 — the standard
        // protobuf encoding minprotobuf produces.
        let req = RlnGifterRequest {
            request_id: "x".into(),
            authentication_type: vec![],
            authentication_payload: vec![],
            identity_commitment: vec![0xff],
            rate_limit: Some(1),
        };
        assert_eq!(
            req.encode(),
            vec![0x0A, 0x01, b'x', 0x12, 0x00, 0x1A, 0x00, 0x22, 0x01, 0xff, 0x28, 0x01]
        );
    }
}
