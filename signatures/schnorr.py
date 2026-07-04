"""Schnorr signatures following BIP-340.

Uses the secp256k1 curve.  Keys and signatures use the x-only public key
convention specified in BIP-340.

Only ``hashlib`` and ``secrets`` are used from the standard library.
"""

from __future__ import annotations

import hashlib
import secrets

from signatures.ecdsa import (
    G,
    N,
    P,
    INF,
    Point,
    point_add,
    point_mul,
    _modinv,
)

# ---------------------------------------------------------------------------
# BIP-340 tagged hashes
# ---------------------------------------------------------------------------

def _tagged_hash(tag: str, data: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


def _int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _bytes_from_int(x: int) -> bytes:
    return x.to_bytes(32, "big")


def _bytes_from_point(pt: Point) -> bytes:
    return _bytes_from_int(pt.x)


def _has_even_y(pt: Point) -> bool:
    return pt.y % 2 == 0


def _lift_x(x: int) -> Point | None:
    """Recover a point from its x coordinate (even y)."""
    if x >= P:
        return None
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        return None
    if y % 2 != 0:
        y = P - y
    return Point(x, y)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def keygen() -> tuple[int, bytes]:
    """Return (secret_key, public_key_x_bytes).

    The secret key is adjusted so that the corresponding public key has an
    even y coordinate, following BIP-340.
    """
    sk = secrets.randbelow(N - 1) + 1
    pk = point_mul(sk, G)
    assert pk is not None
    if not _has_even_y(pk):
        sk = N - sk
        pk = point_mul(sk, G)
        assert pk is not None
    return sk, _bytes_from_point(pk)


def sign(private_key: int, message: bytes) -> bytes:
    """Produce a 64-byte Schnorr signature per BIP-340."""
    pk_point = point_mul(private_key, G)
    assert pk_point is not None

    d = private_key
    if not _has_even_y(pk_point):
        d = N - d

    pk_bytes = _bytes_from_point(pk_point)

    # Deterministic nonce (aux randomness set to zeros for simplicity)
    aux = b"\x00" * 32
    t = bytes(a ^ b for a, b in zip(_bytes_from_int(d), _tagged_hash("BIP0340/aux", aux)))
    k0 = _int_from_bytes(_tagged_hash("BIP0340/nonce", t + pk_bytes + message)) % N
    if k0 == 0:
        raise ValueError("nonce is zero")

    R = point_mul(k0, G)
    assert R is not None
    k = k0 if _has_even_y(R) else N - k0

    e = _int_from_bytes(
        _tagged_hash("BIP0340/challenge", _bytes_from_point(R) + pk_bytes + message)
    ) % N

    sig = _bytes_from_point(R) + _bytes_from_int((k + e * d) % N)
    return sig


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a BIP-340 Schnorr signature.

    *public_key* is the 32-byte x-only public key.
    *signature* is the 64-byte signature.
    """
    if len(public_key) != 32 or len(signature) != 64:
        return False

    px = _int_from_bytes(public_key)
    P_point = _lift_x(px)
    if P_point is None:
        return False

    r = _int_from_bytes(signature[:32])
    s = _int_from_bytes(signature[32:])
    if r >= P or s >= N:
        return False

    e = _int_from_bytes(
        _tagged_hash("BIP0340/challenge", signature[:32] + public_key + message)
    ) % N

    R = point_add(
        point_mul(s, G),
        point_mul(N - e, P_point),
    )

    if R is INF:
        return False
    if not _has_even_y(R):
        return False
    if R.x != r:
        return False
    return True
