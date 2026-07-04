"""Ed25519 signature scheme (RFC 8032).

Implements key generation, signing, and verification over the twisted Edwards
curve -x^2 + y^2 = 1 + d*x^2*y^2  (Curve25519 in Edwards form).

Only ``hashlib`` and ``secrets`` are used from the standard library.
"""

from __future__ import annotations

import hashlib
import secrets

# ---------------------------------------------------------------------------
# Curve25519 (Edwards form) domain parameters
# ---------------------------------------------------------------------------

# Field prime: 2^255 - 19
Q = 2**255 - 19

# Curve order
L = 2**252 + 27742317777372353535851937790883648493

# d parameter for the twisted Edwards curve
D = -121665 * pow(121666, Q - 2, Q) % Q

# Base point y-coordinate: y = 4/5 mod Q
BY = 4 * pow(5, Q - 2, Q) % Q


def _modinv(a: int, p: int) -> int:
    return pow(a, p - 2, p)


def _recover_x(y: int) -> int:
    """Recover x from y for the base point (take the positive root)."""
    y2 = y * y % Q
    x2 = (y2 - 1) * _modinv(D * y2 + 1, Q) % Q
    x = pow(x2, (Q + 3) // 8, Q)
    if (x * x - x2) % Q != 0:
        I = pow(2, (Q - 1) // 4, Q)  # noqa: E741
        x = x * I % Q
    if x % 2 != 0:
        x = Q - x
    return x


BX = _recover_x(BY)
B = (BX, BY, 1, BX * BY % Q)  # extended coordinates (X, Y, Z, T)

# Identity (neutral element)
IDENT = (0, 1, 1, 0)


# ---------------------------------------------------------------------------
# Extended twisted Edwards coordinates arithmetic
# ---------------------------------------------------------------------------

def _point_add(
    p: tuple[int, int, int, int],
    q: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % Q
    b = (y1 + x1) * (y2 + x2) % Q
    c = 2 * t1 * t2 * D % Q
    d = 2 * z1 * z2 % Q
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    x3 = e * f % Q
    y3 = g * h % Q
    z3 = f * g % Q
    t3 = e * h % Q
    return (x3, y3, z3, t3)


def _point_mul(s: int, p: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    result = IDENT
    addend = p
    while s > 0:
        if s & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        s >>= 1
    return result


def _to_affine(p: tuple[int, int, int, int]) -> tuple[int, int]:
    x, y, z, _ = p
    zi = _modinv(z, Q)
    return (x * zi % Q, y * zi % Q)


def _encode_point(p: tuple[int, int, int, int]) -> bytes:
    x, y = _to_affine(p)
    # Set high bit of last byte to the low bit of x
    encoded = (y | ((x & 1) << 255)).to_bytes(32, "little")
    return encoded


def _decode_point(b: bytes) -> tuple[int, int, int, int]:
    if len(b) != 32:
        raise ValueError("invalid point encoding length")
    y = int.from_bytes(b, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    if y >= Q:
        raise ValueError("y >= Q")
    y2 = y * y % Q
    x2 = (y2 - 1) * _modinv(D * y2 + 1, Q) % Q
    if x2 == 0:
        if sign != 0:
            raise ValueError("invalid sign for x=0")
        return (0, y, 1, 0)
    x = pow(x2, (Q + 3) // 8, Q)
    if (x * x - x2) % Q != 0:
        I = pow(2, (Q - 1) // 4, Q)  # noqa: E741
        x = x * I % Q
    if (x * x - x2) % Q != 0:
        raise ValueError("point not on curve")
    if x % 2 != sign:
        x = Q - x
    return (x, y, 1, x * y % Q)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _clamp(a: bytes) -> int:
    """Clamp a 32-byte scalar per Ed25519 spec."""
    a_list = bytearray(a)
    a_list[0] &= 248
    a_list[31] &= 127
    a_list[31] |= 64
    return int.from_bytes(a_list, "little")


def _scalar_from_hash(h: bytes) -> int:
    """Interpret a 64-byte hash as a scalar mod L."""
    return int.from_bytes(h, "little") % L


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def keygen() -> tuple[bytes, bytes]:
    """Generate a 32-byte private key and 32-byte public key."""
    sk = secrets.token_bytes(32)
    h = _sha512(sk)
    a = _clamp(h[:32])
    A = _point_mul(a, B)
    pk = _encode_point(A)
    return sk, pk


def sign(private_key: bytes, message: bytes) -> bytes:
    """Produce a 64-byte Ed25519 signature."""
    h = _sha512(private_key)
    a = _clamp(h[:32])
    prefix = h[32:]
    A = _point_mul(a, B)
    pk = _encode_point(A)

    r = _scalar_from_hash(_sha512(prefix + message))
    R = _point_mul(r, B)
    R_bytes = _encode_point(R)
    k = _scalar_from_hash(_sha512(R_bytes + pk + message))
    s = (r + k * a) % L
    return R_bytes + s.to_bytes(32, "little")


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature."""
    if len(signature) != 64 or len(public_key) != 32:
        return False
    try:
        A = _decode_point(public_key)
        R = _decode_point(signature[:32])
    except (ValueError, OverflowError):
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    k = _scalar_from_hash(_sha512(signature[:32] + public_key + message))
    # Check: [8*s]B == [8]R + [8*k]A
    lhs = _point_mul(8 * s, B)
    rhs = _point_add(_point_mul(8, R), _point_mul(8 * k, A))
    return _to_affine(lhs) == _to_affine(rhs)
