// Pure-Rust Keycard PC/SC client: secure channel + read-path command set
// FEATURE: Keycard device-key RLN membership logos-core module

use crate::apdu::{find_tag, parse_response, Command, Response, CLA_GP};
use crate::crypto;
use rand::RngCore;
use std::time::Duration;

// Detect a card at the READER level via SCardGetStatusChange — without opening a
// card session. Connecting + selecting on every poll (and dropping the handle,
// which resets the card) thrashes the reader; this only reads reader state.
pub fn reader_card_present() -> Result<bool, String> {
    let ctx = pcsc::Context::establish(pcsc::Scope::User).map_err(|e| format!("pcsc ctx: {e}"))?;
    let mut readers_buf = [0u8; 2048];
    let readers: Vec<&std::ffi::CStr> = ctx.list_readers(&mut readers_buf).map_err(|e| format!("readers: {e}"))?.collect();
    let reader = match readers.first() {
        Some(r) => *r,
        None => return Ok(false),
    };
    let mut states = [pcsc::ReaderState::new(reader, pcsc::State::UNAWARE)];
    match ctx.get_status_change(Duration::from_millis(200), &mut states) {
        Ok(()) => Ok(states[0].event_state().contains(pcsc::State::PRESENT)),
        Err(pcsc::Error::Timeout) => Ok(false),
        Err(e) => Err(format!("status change: {e}")),
    }
}

pub const KEYCARD_INSTANCE_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01, 0x01];
pub const STEALTH_EXPORT_PATH: &str = "m/43'/60'/1581'/0'/0'";

const INS_SELECT: u8 = 0xA4;
const INS_OPEN_SECURE_CHANNEL: u8 = 0x10;
const INS_MUTUALLY_AUTHENTICATE: u8 = 0x11;
const INS_PAIR: u8 = 0x12;
const INS_UNPAIR: u8 = 0x13;
const INS_IDENTIFY: u8 = 0x14;
const INS_VERIFY_PIN: u8 = 0x20;
const INS_EXPORT_KEY: u8 = 0xC2;

const P1_PAIR_FIRST: u8 = 0x00;
const P1_PAIR_FINAL: u8 = 0x01;
const P1_EXPORT_DERIVE: u8 = 0x01;
const P2_EXPORT_PRIV_AND_PUB: u8 = 0x00;

const SW_OK: u16 = 0x9000;

struct SecureChannel {
    open: bool,
    secret: [u8; 32],
    eph_pub: Vec<u8>,
    enc_key: [u8; 32],
    mac_key: [u8; 32],
    iv: [u8; 16],
}

pub struct Keycard {
    _ctx: pcsc::Context,
    card: pcsc::Card,
    sc: SecureChannel,
    pub initialized: bool,
    pub instance_uid: Vec<u8>,
    pub pairing_index: u8,
    pairing_key: Vec<u8>,
}

impl Keycard {
    pub fn connect() -> Result<Self, String> {
        let ctx = pcsc::Context::establish(pcsc::Scope::User).map_err(|e| format!("pcsc ctx: {e}"))?;
        let mut buf = [0u8; 2048];
        let readers: Vec<_> = ctx.list_readers(&mut buf).map_err(|e| format!("readers: {e}"))?.collect();
        let reader = *readers.first().ok_or("no reader")?;
        let card = ctx
            .connect(reader, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)
            .map_err(|e| format!("connect (card inserted?): {e}"))?;
        Ok(Keycard {
            _ctx: ctx,
            card,
            sc: SecureChannel {
                open: false,
                secret: [0u8; 32],
                eph_pub: vec![],
                enc_key: [0u8; 32],
                mac_key: [0u8; 32],
                iv: [0u8; 16],
            },
            initialized: false,
            instance_uid: vec![],
            pairing_index: 0,
            pairing_key: vec![],
        })
    }

    fn transmit(&self, cmd: &Command) -> Result<Response, String> {
        let raw = cmd.serialize();
        let mut buf = [0u8; 1024];
        let resp = self.card.transmit(&raw, &mut buf).map_err(|e| format!("transmit: {e}"))?;
        Ok(parse_response(resp))
    }

    fn send_sc(&mut self, mut cmd: Command) -> Result<Response, String> {
        if self.sc.open {
            let enc = crypto::encrypt_data(&cmd.data, &self.sc.enc_key, &self.sc.iv);
            let mut meta = [0u8; 16];
            meta[0] = cmd.cla;
            meta[1] = cmd.ins;
            meta[2] = cmd.p1;
            meta[3] = cmd.p2;
            meta[4] = (enc.len() + 16) as u8;
            self.sc.iv = crypto::calculate_mac(&meta, &enc, &self.sc.mac_key);
            let mut data = self.sc.iv.to_vec();
            data.extend_from_slice(&enc);
            cmd.data = data;
        }
        let resp = self.transmit(&cmd)?;
        if !self.sc.open {
            return Ok(resp);
        }
        if resp.sw != SW_OK {
            return Err(format!("secure channel outer SW {:04X}", resp.sw));
        }
        let rmac = &resp.data[..16];
        let rdata = &resp.data[16..];
        let plain = crypto::decrypt_data(rdata, &self.sc.enc_key, &self.sc.iv);
        let mut rmeta = [0u8; 16];
        rmeta[0] = resp.data.len() as u8;
        let new_iv = crypto::calculate_mac(&rmeta, rdata, &self.sc.mac_key);
        if new_iv != *rmac {
            return Err("invalid response MAC".into());
        }
        self.sc.iv = new_iv;
        Ok(parse_response(&plain))
    }

    pub fn select(&mut self) -> Result<(), String> {
        let mut cmd = Command::new(0x00, INS_SELECT, 0x04, 0x00, KEYCARD_INSTANCE_AID.to_vec());
        cmd.le = Some(0);
        let resp = self.transmit(&cmd)?;
        if resp.sw != SW_OK {
            return Err(format!("SELECT SW {:04X}", resp.sw));
        }
        let card_pub = if resp.data.first() == Some(&0x80) {
            self.initialized = false;
            self.instance_uid = vec![];
            resp.data[2..].to_vec()
        } else {
            let tpl = find_tag(&resp.data, 0xA4).ok_or("no A4 app-info template")?;
            self.initialized = true;
            self.instance_uid = find_tag(&tpl, 0x8F).ok_or("no instance uid")?;
            find_tag(&tpl, 0x80).ok_or("no secure-channel pubkey")?
        };
        let (secret, eph_pub) = crypto::ecdh_generate(&card_pub)?;
        self.sc.secret = secret;
        self.sc.eph_pub = eph_pub;
        self.sc.open = false;
        Ok(())
    }

    pub fn pair(&mut self, pairing_pass: &str) -> Result<(), String> {
        let mut challenge = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut challenge);
        let resp = self.transmit(&Command::new(CLA_GP, INS_PAIR, P1_PAIR_FIRST, 0, challenge.to_vec()))?;
        if resp.sw == 0x6A84 {
            return Err("no available pairing slots".into());
        }
        if resp.sw != SW_OK {
            return Err(format!("PAIR step1 SW {:04X}", resp.sw));
        }
        let card_cryptogram = &resp.data[..32];
        let card_challenge = &resp.data[32..64];
        let secret_hash = crypto::pairing_secret_hash(pairing_pass);
        if crypto::sha256(&[&secret_hash, &challenge]) != card_cryptogram {
            return Err("invalid card cryptogram (wrong pairing password?)".into());
        }
        let client_cryptogram = crypto::sha256(&[&secret_hash, card_challenge]);
        let resp = self.transmit(&Command::new(CLA_GP, INS_PAIR, P1_PAIR_FINAL, 0, client_cryptogram.to_vec()))?;
        if resp.sw != SW_OK {
            return Err(format!("PAIR step2 SW {:04X}", resp.sw));
        }
        self.pairing_index = resp.data[0];
        self.pairing_key = crypto::sha256(&[&secret_hash, &resp.data[1..]]).to_vec();
        Ok(())
    }

    pub fn open_secure_channel(&mut self) -> Result<(), String> {
        let resp = self.transmit(&Command::new(
            CLA_GP,
            INS_OPEN_SECURE_CHANNEL,
            self.pairing_index,
            0,
            self.sc.eph_pub.clone(),
        ))?;
        if resp.sw != SW_OK {
            return Err(format!("OPEN_SECURE_CHANNEL SW {:04X}", resp.sw));
        }
        let (enc, mac, iv) = crypto::derive_session_keys(&self.sc.secret, &self.pairing_key, &resp.data);
        self.sc.enc_key = enc;
        self.sc.mac_key = mac;
        self.sc.iv = iv;
        self.sc.open = true;
        let mut data = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut data);
        let resp = self.send_sc(Command::new(CLA_GP, INS_MUTUALLY_AUTHENTICATE, 0, 0, data.to_vec()))?;
        if resp.sw != SW_OK {
            return Err(format!("MUTUALLY_AUTHENTICATE SW {:04X}", resp.sw));
        }
        Ok(())
    }

    pub fn verify_pin(&mut self, pin: &str) -> Result<(), String> {
        let resp = self.send_sc(Command::new(CLA_GP, INS_VERIFY_PIN, 0, 0, pin.as_bytes().to_vec()))?;
        if resp.sw != SW_OK {
            if (resp.sw & 0x63C0) == 0x63C0 {
                return Err(format!("wrong PIN, {} attempts left", resp.sw & 0x000F));
            }
            return Err(format!("VERIFY_PIN SW {:04X}", resp.sw));
        }
        Ok(())
    }

    pub fn export_key(&mut self, path: &str) -> Result<Vec<u8>, String> {
        let mut data = Vec::new();
        for s in decode_path(path)? {
            data.extend_from_slice(&s.to_be_bytes());
        }
        let resp = self.send_sc(Command::new(CLA_GP, INS_EXPORT_KEY, P1_EXPORT_DERIVE, P2_EXPORT_PRIV_AND_PUB, data))?;
        if resp.sw != SW_OK {
            return Err(format!("EXPORT_KEY SW {:04X}", resp.sw));
        }
        let tpl = find_tag(&resp.data, 0xA1).ok_or("no A1 export template")?;
        find_tag(&tpl, 0x81).ok_or("no private key in export".into())
    }

    pub fn identify(&mut self, challenge: &[u8]) -> Result<Vec<u8>, String> {
        let resp = self.send_sc(Command::new(CLA_GP, INS_IDENTIFY, 0, 0, challenge.to_vec()))?;
        if resp.sw != SW_OK {
            return Err(format!("IDENTIFY SW {:04X}", resp.sw));
        }
        Ok(resp.data)
    }

    pub fn unpair(&mut self, index: u8) -> Result<(), String> {
        let resp = self.send_sc(Command::new(CLA_GP, INS_UNPAIR, index, 0, vec![]))?;
        if resp.sw != SW_OK {
            return Err(format!("UNPAIR SW {:04X}", resp.sw));
        }
        Ok(())
    }
}

fn decode_path(path: &str) -> Result<Vec<u32>, String> {
    let mut parts = path.split('/');
    let head = parts.next().ok_or("empty path")?;
    if head != "m" && head != "M" {
        return Err("only master-rooted paths (m/...) supported".into());
    }
    let mut out = Vec::new();
    for p in parts {
        if p.is_empty() {
            continue;
        }
        let hardened = p.ends_with('\'') || p.ends_with('h') || p.ends_with('H');
        let mut n: u32 = p.trim_end_matches(['\'', 'h', 'H']).parse().map_err(|_| format!("bad path segment {p}"))?;
        if hardened {
            n |= 0x8000_0000;
        }
        out.push(n);
    }
    Ok(out)
}
