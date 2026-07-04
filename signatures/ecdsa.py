"""ECDSA over the secp256k1 curve.

Implements key generation, signing (RFC 6979-style deterministic k is NOT used
here -- we use ``secrets`` for nonce generation), and verification following
the standard ECDSA algorithm.

Only ``hashlib`` and ``secrets`` are used from the standard library; all
elliptic-curve arithmetic is done from scratch.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# secp256k1 domain parameters
# ---------------------------------------------------------------------------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A = 0
B = 7
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

INF = None  # point at infinity sentinel


# ---------------------------------------------------------------------------
# Modular arithmetic helpers
# ---------------------------------------------------------------------------

def _modinv(a: int, m: int) -> int:
    """Modular inverse via extended Euclidean algorithm."""
    if a < 0:
        a = a % m
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m


def _extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


# ---------------------------------------------------------------------------
# Elliptic-curve point operations (affine coordinates)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Point:
    x: int
    y: int


def point_add(p1: Point | None, p2: Point | None) -> Point | None:
    if p1 is INF:
        return p2
    if p2 is INF:
        return p1
    if p1.x == p2.x and p1.y != p2.y:
        return INF
    if p1.x == p2.x and p1.y == p2.y:
        # Point doubling
        lam = (3 * p1.x * p1.x + A) * _modinv(2 * p1.y, P) % P
    else:
        lam = (p2.y - p1.y) * _modinv(p2.x - p1.x, P) % P
    x3 = (lam * lam - p1.x - p2.x) % P
    y3 = (lam * (p1.x - x3) - p1.y) % P
    return Point(x3, y3)


def point_mul(k: int, point: Point | None) -> Point | None:
    """Scalar multiplication via double-and-add."""
    result: Point | None = INF
    addend = point
    k = k % N
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


G = Point(GX, GY)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def keygen() -> tuple[int, Point]:
    """Generate a private key (int) and public key (Point)."""
    sk = secrets.randbelow(N - 1) + 1
    pk = point_mul(sk, G)
    assert pk is not None
    return sk, pk


def sign(private_key: int, message: bytes) -> tuple[int, int]:
    """Sign *message* and return (r, s)."""
    z = int.from_bytes(hashlib.sha256(message).digest(), "big") % N
    while True:
        k = secrets.randbelow(N - 1) + 1
        R = point_mul(k, G)
        assert R is not None
        r = R.x % N
        if r == 0:
            continue
        s = (_modinv(k, N) * (z + r * private_key)) % N
        if s == 0:
            continue
        # Enforce low-s (BIP-62)
        if s > N // 2:
            s = N - s
        return r, s


def verify(public_key: Point, message: bytes, signature: tuple[int, int]) -> bool:
    """Verify an ECDSA signature."""
    r, s = signature
    if not (1 <= r < N and 1 <= s < N):
        return False
    z = int.from_bytes(hashlib.sha256(message).digest(), "big") % N
    s_inv = _modinv(s, N)
    u1 = (z * s_inv) % N
    u2 = (r * s_inv) % N
    R = point_add(point_mul(u1, G), point_mul(u2, public_key))
    if R is INF:
        return False
    return R.x % N == r
