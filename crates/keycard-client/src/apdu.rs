// APDU command serialization and BER-TLV response parsing for the Keycard
// FEATURE: Keycard device-key RLN membership logos-core module

pub const CLA_GP: u8 = 0x80;

#[derive(Clone)]
pub struct Command {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
    pub le: Option<u8>,
}

pub struct Response {
    pub data: Vec<u8>,
    pub sw: u16,
}

impl Command {
    pub fn new(cla: u8, ins: u8, p1: u8, p2: u8, data: Vec<u8>) -> Self {
        Command { cla, ins, p1, p2, data, le: None }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = vec![self.cla, self.ins, self.p1, self.p2];
        if !self.data.is_empty() {
            out.push(self.data.len() as u8);
            out.extend_from_slice(&self.data);
        }
        if let Some(le) = self.le {
            out.push(le);
        }
        out
    }
}

pub fn parse_response(raw: &[u8]) -> Response {
    let n = raw.len();
    if n < 2 {
        return Response { data: vec![], sw: 0 };
    }
    let sw = ((raw[n - 2] as u16) << 8) | (raw[n - 1] as u16);
    Response { data: raw[..n - 2].to_vec(), sw }
}

pub fn find_tag(data: &[u8], tag: u8) -> Option<Vec<u8>> {
    let mut i = 0;
    while i < data.len() {
        let t = data[i];
        i += 1;
        if i >= data.len() {
            return None;
        }
        let len = read_len(data, &mut i)?;
        if i + len > data.len() {
            return None;
        }
        if t == tag {
            return Some(data[i..i + len].to_vec());
        }
        i += len;
    }
    None
}

fn read_len(data: &[u8], i: &mut usize) -> Option<usize> {
    let b = data[*i];
    *i += 1;
    if b < 0x80 {
        Some(b as usize)
    } else {
        let n = (b & 0x7f) as usize;
        let mut len = 0usize;
        for _ in 0..n {
            if *i >= data.len() {
                return None;
            }
            len = (len << 8) | data[*i] as usize;
            *i += 1;
        }
        Some(len)
    }
}
