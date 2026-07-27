#!/usr/bin/env python3
# Mint synthetic Keycard IDENTIFY_CARD attestations for CI / e2e testing.
# Pure python, no external deps (same style as the mix e2e's keys.py), so it
# runs on the host or in any container. Mirrors rln-zone-sequencer's
# mint_attestation test harness: the throwaway CA recoverably signs
# SHA256(ident_pub); the "card" DER-signs the raw commitment-bound challenge
# SHA256("logos/rln/keycard-attest/1" || id_commitment); both wrapped in the
# A0 { 8A cert, 30 der } TLV that keycard_attest.nim / the gifter verifies.
#
#   mint_attest.py mint <ca_priv_hex> <card_priv_hex> <id_commitment_hex>
#       -> JSON {tlv, challenge, ca_pub, ident_pub, nullifier}
#   mint_attest.py pub <priv_hex>      -> compressed secp256k1 pubkey hex
#   mint_attest.py selftest            -> verify keccak + curve against fixtures
#
# NOT FOR PRODUCTION: nonces are sha256-derived (deterministic output for
# fixed inputs), keys are throwaway test material.
import hashlib
import json
import sys

# ---- secp256k1 ----
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _inv(a: int, m: int) -> int:
    return pow(a, -1, m)


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % _P == 0:
        return None
    if p == q:
        lam = (3 * p[0] * p[0]) * _inv(2 * p[1], _P) % _P
    else:
        lam = (q[1] - p[1]) * _inv(q[0] - p[0], _P) % _P
    x = (lam * lam - p[0] - q[0]) % _P
    return (x, (lam * (p[0] - x) - p[1]) % _P)


def _mul(k: int, p):
    r = None
    while k:
        if k & 1:
            r = _add(r, p)
        p = _add(p, p)
        k >>= 1
    return r


def _pub_point(priv: int):
    return _mul(priv, (_GX, _GY))


def compressed_pub(priv: int) -> bytes:
    x, y = _pub_point(priv)
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def uncompressed_pub(priv: int) -> bytes:
    x, y = _pub_point(priv)
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def sign_prehash(priv: int, prehash: bytes):
    """ECDSA over the raw 32-byte prehash. Returns (r, s, recid), low-S."""
    z = int.from_bytes(prehash, "big")
    ctr = 0
    while True:
        k = (
            int.from_bytes(
                hashlib.sha256(
                    priv.to_bytes(32, "big") + prehash + ctr.to_bytes(4, "big")
                ).digest(),
                "big",
            )
            % _N
        )
        ctr += 1
        if k == 0:
            continue
        rx, ry = _mul(k, (_GX, _GY))
        if rx >= _N:
            continue
        r = rx % _N
        if r == 0:
            continue
        s = _inv(k, _N) * (z + r * priv) % _N
        if s == 0:
            continue
        recid = ry & 1
        if s > _N // 2:
            s = _N - s
            recid ^= 1
        return r, s, recid


def der_encode(r: int, s: int) -> bytes:
    def enc_int(v: int) -> bytes:
        b = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b

    body = enc_int(r) + enc_int(s)
    return b"\x30" + bytes([len(body)]) + body


# ---- keccak-256 (Keccak team's CompactFIPS202 permutation) ----
def _rol64(a, n):
    return ((a >> (64 - (n % 64))) + (a << (n % 64))) % (1 << 64)


def _keccak_f(lanes):
    R = 1
    for _ in range(24):
        C = [lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4] for x in range(5)]
        D = [C[(x + 4) % 5] ^ _rol64(C[(x + 1) % 5], 1) for x in range(5)]
        lanes = [[lanes[x][y] ^ D[x] for y in range(5)] for x in range(5)]
        (x, y) = (1, 0)
        current = lanes[x][y]
        for t in range(24):
            (x, y) = (y, (2 * x + 3 * y) % 5)
            (current, lanes[x][y]) = (lanes[x][y], _rol64(current, (t + 1) * (t + 2) // 2))
        for y in range(5):
            T = [lanes[x][y] for x in range(5)]
            for x in range(5):
                lanes[x][y] = T[x] ^ ((~T[(x + 1) % 5]) & T[(x + 2) % 5])
        for j in range(7):
            R = ((R << 1) ^ ((R >> 7) * 0x71)) % 256
            if R & 2:
                lanes[0][0] ^= 1 << ((1 << j) - 1)
    return lanes


def keccak256(data: bytes) -> bytes:
    rate = 136
    msg = bytearray(data) + b"\x01"
    msg += b"\x00" * (-len(msg) % rate)
    msg[-1] ^= 0x80
    lanes = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        block = msg[off : off + rate]
        for i in range(rate // 8):
            lanes[i % 5][i // 5] ^= int.from_bytes(block[8 * i : 8 * i + 8], "little")
        lanes = _keccak_f(lanes)
    out = b""
    for i in range(4):
        out += lanes[i % 5][i // 5].to_bytes(8, "little")
    return out


# ---- attestation ----
DOMAIN = b"logos/rln/keycard-attest/1"


def tlv(tag: int, value: bytes) -> bytes:
    if len(value) < 0x80:
        return bytes([tag, len(value)]) + value
    if len(value) <= 0xFF:
        return bytes([tag, 0x81, len(value)]) + value
    return bytes([tag, 0x82, len(value) >> 8, len(value) & 0xFF]) + value


def bound_challenge(id_commitment: bytes) -> bytes:
    return hashlib.sha256(DOMAIN + id_commitment).digest()


def mint(ca_priv: int, card_priv: int, id_commitment: bytes) -> dict:
    ident_pub = compressed_pub(card_priv)
    prehash = hashlib.sha256(ident_pub).digest()
    r, s, recid = sign_prehash(ca_priv, prehash)
    cert = ident_pub + r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([recid])

    challenge = bound_challenge(id_commitment)
    cr, cs, _ = sign_prehash(card_priv, challenge)
    template = tlv(0x8A, cert) + der_encode(cr, cs)
    return {
        "tlv": tlv(0xA0, template).hex(),
        "challenge": challenge.hex(),
        "ca_pub": compressed_pub(ca_priv).hex(),
        "ident_pub": ident_pub.hex(),
        "nullifier": keccak256(ident_pub).hex(),
    }


def selftest() -> None:
    assert (
        keccak256(b"").hex()
        == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    ), "keccak vector"
    key = int("b880df1f571109e646f641636794dfe7ffefc2aab19290ba0d720c407758304d", 16)
    addr = "0x" + keccak256(uncompressed_pub(key)[1:])[12:].hex()
    assert addr == "0x8e3d4d0a713087e2263e2fcdec894c283c777dcc", f"eth addr {addr}"
    r, s, recid = sign_prehash(key, hashlib.sha256(b"probe").digest())
    assert 0 < r < _N and 0 < s <= _N // 2 and recid in (0, 1), "sign shape"
    print("selftest ok")


def main() -> None:
    if len(sys.argv) >= 2 and sys.argv[1] == "selftest":
        selftest()
    elif len(sys.argv) == 3 and sys.argv[1] == "pub":
        print(compressed_pub(int(sys.argv[2], 16)).hex())
    elif len(sys.argv) == 5 and sys.argv[1] == "mint":
        out = mint(
            int(sys.argv[2], 16), int(sys.argv[3], 16), bytes.fromhex(sys.argv[4])
        )
        print(json.dumps(out))
    else:
        sys.exit(__doc__ or "usage: mint_attest.py mint|pub|selftest ...")


if __name__ == "__main__":
    main()
