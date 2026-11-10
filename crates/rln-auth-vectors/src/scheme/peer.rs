//! The `peer` scheme: no signature at all. The requester's identity is the
//! libp2p peer id behind the secure channel the request arrived on — the
//! Noise handshake proved the key, and the commitment travels on that same
//! stream, so the stream itself binds commitment and identity. Nothing in
//! the payload is signed: like eth (`auth-vectors.md` §4), `rate_max` and
//! `audience` are not bound; unlike eth, a payload cannot be replayed from
//! another peer because the identity is the transport's, not the payload's.

use std::any::Any;

use base58::FromBase58;
#[cfg(feature = "verify")]
use rln_auth_vector::{reason, Binding, Check, Decoded, Outcome, Scheme, Transport};
use rln_auth_vector::{strip_0x, Identity};

pub const NAME: &str = "peer";

/// A libp2p peer id: the multihash bytes, lowercase hex.
pub struct PeerId(pub String);

impl Identity for PeerId {
    fn canonical(&self) -> String {
        self.0.clone()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A peer id as libp2p prints it (base58btc multihash, `12D3Koo…` /
/// `16Uiu2…`) or as hex — normalised to the multihash's lowercase hex, the
/// one form that survives the gifter's lowercasing.
pub fn parse_peer_id(s: &str) -> Result<String, String> {
    let s = s.trim();
    let h = strip_0x(s);
    let bytes =
        if !h.is_empty() && h.len().is_multiple_of(2) && h.bytes().all(|b| b.is_ascii_hexdigit()) {
            hex::decode(h).map_err(|e| format!("peer id '{s}': {e}"))?
        } else {
            s.from_base58()
                .map_err(|e| format!("peer id '{s}': neither hex nor base58 ({e:?})"))?
        };
    // A multihash with one-byte code and length varints (every libp2p
    // identity key kind: identity/ed25519 38 bytes, sha256/secp256k1 34).
    if bytes.len() < 3 || bytes[1] as usize != bytes.len() - 2 {
        return Err(format!(
            "peer id '{s}': {} bytes is not a multihash",
            bytes.len()
        ));
    }
    Ok(hex::encode(bytes))
}

pub struct Peer;

#[cfg(feature = "verify")]
impl Scheme for Peer {
    fn name(&self) -> &'static str {
        NAME
    }
    fn identity_noun(&self) -> &'static str {
        "peer"
    }
    fn parse_identity(&self, s: &str) -> Result<String, String> {
        parse_peer_id(s)
    }
    /// The part is empty: there is nothing to sign with.
    fn decode<'a>(&self, body: &'a [u8]) -> Outcome<Decoded<'a>> {
        let (part, rest) = body.split_at(0);
        Outcome::Ok(Decoded {
            claimed: None,
            part,
            rest,
        })
    }
    fn verify(
        &self,
        _cfg: &dyn Any,
        _b: &Binding,
        _digest: &[u8; 32],
        _d: &Decoded<'_>,
        t: &Transport<'_>,
    ) -> Check<Box<dyn Identity>> {
        let Some(raw) = t.peer_id.map(str::trim).filter(|p| !p.is_empty()) else {
            return Err(reason::TRANSPORT_PEER_UNKNOWN.into());
        };
        // A peer id the bridge reported but this crate cannot read is the
        // host's problem, not the requester's.
        Ok(Outcome::Ok(Box::new(PeerId(parse_peer_id(raw)?))))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // Peer ids as libp2p prints them: an ed25519 key (identity multihash,
    // 38 bytes, 12D3Koo…), a secp256k1 key as libp2p_module mints them
    // (identity multihash, 39 bytes, 16Uiu2…), and a hashed key (sha256
    // multihash, 34 bytes, Qm…).
    pub(crate) const ED25519_B58: &str = "12D3KooWA1yXQfKD3c8QznGkpf1ZepPH1FQKwAwMxbTh1feQsapZ";
    pub(crate) const SECP_B58: &str = "16Uiu2HAkyiMKmjcAj4FS5jot1jMZB73mnY3wJnSTKZmTBhrFJEaT";
    pub(crate) const QM_B58: &str = "QmQfvdZYmpvysswRYhPy2cDQPv47pWooqarKGq98uJgpSk";

    #[test]
    fn base58_and_hex_normalise_to_the_same_multihash_hex() {
        let ed = parse_peer_id(ED25519_B58).unwrap();
        assert!(ed.starts_with("00240801"), "{ed}");
        assert_eq!(ed.len(), 76);
        assert_eq!(
            parse_peer_id(&format!("0x{}", ed.to_uppercase())).unwrap(),
            ed
        );
        let secp = parse_peer_id(SECP_B58).unwrap();
        assert!(secp.starts_with("00250802"), "{secp}");
        assert_eq!(secp.len(), 78);
        let qm = parse_peer_id(QM_B58).unwrap();
        assert!(qm.starts_with("1220"), "{qm}");
        assert_eq!(qm.len(), 68);
        assert!(parse_peer_id("").is_err());
        assert!(parse_peer_id("0x1220")
            .unwrap_err()
            .contains("not a multihash"));
        assert!(parse_peer_id("not*base58")
            .unwrap_err()
            .contains("neither hex nor base58"));
    }

    #[cfg(feature = "verify")]
    #[test]
    fn the_identity_is_the_transports_or_nothing() {
        let d = match Peer.decode(b"tail") {
            Outcome::Ok(d) => d,
            Outcome::Reject(r) => panic!("{r}"),
        };
        assert!(d.part.is_empty() && d.rest == b"tail" && d.claimed.is_none());
        let b = Binding {
            id_commitment: [1; 32],
            rate_max: 1,
            audience: String::new(),
        };
        let ok = Peer
            .verify(
                &(),
                &b,
                &[0; 32],
                &d,
                &Transport {
                    peer_id: Some(SECP_B58),
                },
            )
            .unwrap();
        let Outcome::Ok(id) = ok else { panic!() };
        assert_eq!(id.canonical(), parse_peer_id(SECP_B58).unwrap());
        let Err(e) = Peer.verify(&(), &b, &[0; 32], &d, &Transport::default()) else {
            panic!()
        };
        assert_eq!(e, reason::TRANSPORT_PEER_UNKNOWN);
        assert!(Peer
            .verify(
                &(),
                &b,
                &[0; 32],
                &d,
                &Transport {
                    peer_id: Some("??")
                }
            )
            .is_err());
    }
}
